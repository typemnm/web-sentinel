use anyhow::Result;
use tracing::{info, warn};

use crate::core::scanner::{Finding, FindingCategory, ScanConfig, ScanContext, Severity};
use crate::db::cve::CveDb;
use crate::db::state::StateDb;
use crate::network::crawler::Crawler;
use crate::network::http::HttpClient;
use crate::network::port::PortScanner;
use crate::network::fingerprint::Fingerprinter;
use crate::network::analyzer::ResponseAnalyzer;
use crate::network::scope::ScopeGuard;
use crate::report::json::ReportWriter;
use crate::scripting::engine::ScriptEngine;

/// Top-level orchestrator — ⑪ Arc<Mutex<Vec<Finding>>> 제거
pub struct Orchestrator {
    ctx: ScanContext,
}

impl Orchestrator {
    pub async fn new(config: ScanConfig) -> Result<Self> {
        Ok(Self { ctx: ScanContext::new(config) })
    }

    pub async fn run(&mut self) -> Result<()> {
        let target = self.ctx.config.target.clone();
        info!("Starting scan: {}", target);

        let state = StateDb::open("sentinel_state.db")?;
        state.set("scan:target", &target)?;
        state.set("scan:status", "running")?;
        state.mark_visited(&target)?;

        let http_client   = HttpClient::new(&self.ctx)?;
        let port_scanner  = PortScanner::new(self.ctx.clone());
        let fingerprinter = Fingerprinter::new();
        let host          = extract_host(&target);

        // ② Phase 1(포트) + Phase 2(핑거프린팅) 동시 실행
        info!("[Phase 1+2] Port scan & fingerprinting in parallel...");
        let (ports_result, fp_result) = tokio::join!(
            async {
                if self.ctx.config.port_scan_enabled {
                    port_scanner.scan(&host).await
                } else {
                    Ok(vec![])
                }
            },
            fingerprinter.detect(&target, &http_client)
        );

        // Phase 1 결과 수집
        let mut all_findings: Vec<Finding> = Vec::new();
        for port in ports_result? {
            all_findings.push(Finding::new(
                Severity::Info,
                FindingCategory::OpenPort,
                format!("Open port: {}", port),
                format!("Port {} is open on {}", port, host),
                format!("{}:{}", host, port),
            ));
        }

        // Phase 2 결과 수집
        let fp_result = fp_result?;
        for tech in &fp_result.technologies {
            all_findings.push(Finding::new(
                Severity::Info,
                FindingCategory::TechStack,
                format!("Technology detected: {}", tech.name),
                format!(
                    "Detected {} {} on target",
                    tech.name,
                    tech.version.as_deref().unwrap_or("")
                ),
                target.clone(),
            ));
        }

        // Phase 3: CVE 상관관계 (fingerprint 결과 의존 → 직렬 유지)
        info!("[Phase 3] CVE correlation...");
        let cve_db = CveDb::open("sentinel_cves.db")?;
        cve_db.seed_known_cves()?;
        for tech in &fp_result.technologies {
            if let Some(version) = &tech.version {
                for cve in cve_db.search(&tech.name, version)? {
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::Cve,
                        format!("CVE: {}", cve.id),
                        cve.description.clone(),
                        target.clone(),
                    );
                    f.cve = Some(cve.id.clone());
                    all_findings.push(f);
                }
            }
        }

        // Phase 3.5: Recursive Crawl — discover links and forms at depth
        let max_depth = self.ctx.config.max_crawl_depth;
        let max_urls = self.ctx.config.max_crawl_urls;
        info!("[Phase 3.5] Recursive crawling target (max_depth={}, max_urls={})...",
              max_depth, max_urls);
        let scope = ScopeGuard::new(&self.ctx.config.scope);
        let crawler = Crawler::new(http_client.clone(), scope.clone());
        let crawl_result = match crawler.crawl_recursive(
            &target,
            max_depth,
            max_urls,
        ).await {
            Ok(cr) => {
                info!(
                    "Crawl complete: {} links, {} forms discovered",
                    cr.urls.len(),
                    cr.forms.len()
                );
                cr
            }
            Err(e) => {
                warn!("Crawl failed: {:#}", e);
                crate::network::crawler::CrawlResult::default()
            }
        };

        // Build tech context string from fingerprint for priority adjustments
        let detected_techs: Vec<String> = fp_result.technologies
            .iter()
            .map(|t| t.name.to_lowercase())
            .collect();

        // ② Phase 4(HTTP 체크) + Phase 5(Lua) 동시 실행
        info!("[Phase 4+5] HTTP checks & Lua scripts in parallel...");
        let analyzer = ResponseAnalyzer::new(
            self.ctx.clone(), http_client.clone(), scope,
        );

        let scripts_dir   = self.ctx.config.scripts_dir.clone();
        let scripts_exist = scripts_dir.exists();
        let ctx_clone     = self.ctx.clone();
        let client_clone  = http_client.clone();
        let target_clone  = target.clone();

        let crawl_urls = crawl_result.urls.clone();
        let crawl_forms = crawl_result.forms.clone();

        let (http_findings, script_findings) = tokio::join!(
            analyzer.run(&target, &crawl_urls, &crawl_forms),
            async move {
                if scripts_exist {
                    let mut engine =
                        ScriptEngine::new(ctx_clone, client_clone).await?;
                    engine.run_all(&target_clone).await
                } else {
                    warn!("Scripts directory not found, skipping: {:?}", scripts_dir);
                    Ok(vec![])
                }
            }
        );

        all_findings.extend(http_findings?);
        match script_findings {
            Ok(f) => all_findings.extend(f),
            Err(e) => warn!("Script phase error: {:#}", e),
        }

        // Phase 6: 브라우저 XSS (직렬 유지 — Chrome 단일 프로세스)
        if self.ctx.config.browser_enabled {
            info!("[Phase 6] Browser-based XSS detection...");
            match crate::browser::controller::scan_with_browser(&target).await {
                Ok(f) => all_findings.extend(f),
                Err(e) => warn!("Browser phase error: {:#}", e),
            }
        }

        // Enrich findings: add tech-stack context to descriptions when relevant
        for finding in &mut all_findings {
            let title_lower = finding.title.to_lowercase();
            let desc_lower = finding.description.to_lowercase();
            let combined = format!("{} {}", title_lower, desc_lower);

            // If PHP detected and finding relates to LFI/traversal/SSTI → note it
            if detected_techs.iter().any(|t| t.contains("php")) {
                if combined.contains("traversal") || combined.contains("lfi") || combined.contains("ssti") || combined.contains("template") {
                    finding.description.push_str(" [PHP detected on target — higher exploitation likelihood]");
                }
            }
            // If Java detected and finding relates to deserialization/SSTI
            if detected_techs.iter().any(|t| t.contains("java") || t.contains("spring") || t.contains("tomcat")) {
                if combined.contains("deseriali") || combined.contains("freemarker") || combined.contains("thymeleaf") {
                    finding.description.push_str(" [Java/Spring detected — higher exploitation likelihood]");
                }
            }
            // If Python detected and finding relates to SSTI (Jinja2)
            if detected_techs.iter().any(|t| t.contains("python") || t.contains("flask") || t.contains("django")) {
                if combined.contains("ssti") || combined.contains("jinja") || combined.contains("template") {
                    finding.description.push_str(" [Python/Flask detected — Jinja2 SSTI likely exploitable]");
                }
            }
        }

        // Deduplicate & aggregate findings
        let all_findings = crate::report::dedup::deduplicate(all_findings);

        // 리포트 작성
        info!("Scan complete. {} findings.", all_findings.len());
        let writer = ReportWriter::new(self.ctx.config.output.clone());
        writer.write(&target, &all_findings).await?;
        info!("Report written to: {}", self.ctx.config.output.display());

        state.set("scan:status", "done")?;
        state.flush()?;

        Ok(())
    }
}

fn extract_host(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        parsed.host_str().unwrap_or(url).to_string()
    } else {
        url.to_string()
    }
}
