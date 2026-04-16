pub mod config;
pub mod executor;
pub mod prompt;
pub mod provider;
pub mod types;

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::core::scanner::{Finding, FindingCategory, ScanConfig, Severity};
use crate::network::http::HttpClient;
use crate::network::scope::ScopeGuard;

use self::executor::AttackExecutor;
use self::prompt::{build_finding_prompt, SYSTEM_PROMPT};
use self::provider::{LlmProvider, OpenAiCompatProvider};
use self::types::{LlmStats, PromptMessage};

/// Output of the LLM phase: new findings to append + stats for reporting.
pub struct LlmPhaseOutput {
    pub new_findings: Vec<Finding>,
    pub stats: LlmStats,
}

pub struct LlmPhase;

impl LlmPhase {
    /// Run the LLM analysis phase over existing findings.
    ///
    /// Filters by severity threshold, sends each finding to the LLM,
    /// optionally executes the generated attacks, and returns new findings.
    pub async fn run(
        config: &ScanConfig,
        existing_findings: &[Finding],
        scan_http_client: &HttpClient,
        scope: &ScopeGuard,
    ) -> Result<LlmPhaseOutput> {
        let llm_config = &config.llm_config;
        let mut stats = LlmStats::default();
        let mut new_findings: Vec<Finding> = Vec::new();

        let provider: Box<dyn LlmProvider> = match llm_config.provider.as_str() {
            "openai-compat" => Box::new(OpenAiCompatProvider::new(llm_config)?),
            other => anyhow::bail!(
                "Unsupported LLM provider: '{}'. Only 'openai-compat' is supported.",
                other
            ),
        };

        let executor = AttackExecutor::new(scan_http_client.clone());

        // Filter findings by severity threshold, take at most max_findings
        let candidates: Vec<&Finding> = existing_findings
            .iter()
            .filter(|f| llm_config.min_severity.accepts(&f.severity))
            .take(llm_config.max_findings)
            .collect();

        if candidates.is_empty() {
            info!(
                "LLM phase: no findings meet severity threshold ({:?}), skipping",
                llm_config.min_severity
            );
            return Ok(LlmPhaseOutput { new_findings, stats });
        }

        info!(
            "LLM phase: analyzing {} of {} findings (threshold={:?}, dry_run={})",
            candidates.len(),
            existing_findings.len(),
            llm_config.min_severity,
            llm_config.dry_run,
        );

        let system_msg = PromptMessage {
            role: "system".to_string(),
            content: SYSTEM_PROMPT.to_string(),
        };

        for finding in &candidates {
            stats.findings_analyzed += 1;
            stats.api_calls += 1;

            let user_msg = build_finding_prompt(finding, llm_config.max_evidence_chars);
            let messages = vec![system_msg.clone(), user_msg];

            let (analysis, prompt_tok, completion_tok) =
                match provider.chat_completion(&messages).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("LLM API error for finding {}: {:#}", finding.id, e);
                        stats.errors += 1;
                        continue;
                    }
                };

            stats.prompt_tokens += prompt_tok;
            stats.completion_tokens += completion_tok;

            let attacks: Vec<_> = analysis
                .attacks
                .into_iter()
                .take(llm_config.max_attacks_per_finding)
                .collect();

            stats.attacks_generated += attacks.len();

            debug!(
                "LLM analysis for '{}': confidence={:.2}, {} attacks generated",
                finding.title,
                analysis.confidence,
                attacks.len()
            );

            if attacks.is_empty() {
                // No attacks — record analysis finding if confidence is meaningful
                if analysis.confidence > 0.3 {
                    let mut f = Finding::new(
                        finding.severity.clone(),
                        FindingCategory::LlmAnalysis,
                        format!("[LLM] {}", finding.title),
                        format!(
                            "LLM analysis (confidence {:.0}%): {}",
                            analysis.confidence * 100.0,
                            analysis.analysis
                        ),
                        finding.url.clone(),
                    );
                    f.remediation = analysis.remediation.or_else(|| finding.remediation.clone());
                    f.cve = finding.cve.clone();
                    new_findings.push(f);
                }
                continue;
            }

            if llm_config.dry_run {
                // Dry-run: record each attack as an analysis finding without executing
                for spec in &attacks {
                    let mut f = Finding::new(
                        finding.severity.clone(),
                        FindingCategory::LlmAnalysis,
                        format!("[LLM/dry-run] {}", finding.title),
                        format!(
                            "LLM proposed attack (confidence {:.0}%): {} {} — {}",
                            analysis.confidence * 100.0,
                            spec.method,
                            spec.url,
                            spec.rationale
                        ),
                        finding.url.clone(),
                    );
                    f.remediation = analysis
                        .remediation
                        .clone()
                        .or_else(|| finding.remediation.clone());
                    f.cve = finding.cve.clone();
                    new_findings.push(f);
                }
                continue;
            }

            // Execute attacks via the scan's HttpClient (inherits rate limiter + scope)
            let results = executor.execute_attacks(&attacks, scope).await;

            let mut any_confirmed = false;
            for result in &results {
                stats.attacks_executed += 1;
                if result.confirmed {
                    stats.attacks_confirmed += 1;
                    any_confirmed = true;
                    let mut f = Finding::new(
                        Severity::Critical,
                        FindingCategory::LlmExploit,
                        format!("[LLM Confirmed] {}", finding.title),
                        format!(
                            "LLM-generated attack confirmed the vulnerability. \
                             {} {} returned HTTP {}. Rationale: {}",
                            result.spec.method,
                            result.spec.url,
                            result.response_status,
                            result.spec.rationale,
                        ),
                        result.spec.url.clone(),
                    );
                    f.evidence = Some(result.response_body_snippet.clone());
                    f.remediation = analysis
                        .remediation
                        .clone()
                        .or_else(|| finding.remediation.clone());
                    f.cve = finding.cve.clone();
                    new_findings.push(f);
                }
            }

            // Record analysis finding if no attacks confirmed
            if !any_confirmed && analysis.confidence > 0.3 {
                let mut f = Finding::new(
                    finding.severity.clone(),
                    FindingCategory::LlmAnalysis,
                    format!("[LLM Unconfirmed] {}", finding.title),
                    format!(
                        "LLM analysis (confidence {:.0}%): {}. \
                         {} attack(s) executed, none confirmed exploitation.",
                        analysis.confidence * 100.0,
                        analysis.analysis,
                        results.len()
                    ),
                    finding.url.clone(),
                );
                f.remediation = analysis.remediation.or_else(|| finding.remediation.clone());
                f.cve = finding.cve.clone();
                new_findings.push(f);
            }
        }

        Ok(LlmPhaseOutput { new_findings, stats })
    }
}
