use tracing::{debug, warn};

use crate::network::http::HttpClient;
use crate::network::scope::ScopeGuard;

use super::types::{AttackResult, AttackSpec, SuccessIndicator};

/// Executes LLM-generated attack specs through the scan's HttpClient.
/// All requests inherit the scan's rate limiter and scope guard.
pub struct AttackExecutor {
    client: HttpClient,
}

/// Maximum response body stored in AttackResult evidence.
const MAX_EVIDENCE_SNIPPET: usize = 2048;

/// Allowed HTTP methods for LLM-generated attacks.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "HEAD", "OPTIONS"];

impl AttackExecutor {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Execute a batch of attack specs. Skips out-of-scope or unsupported specs.
    pub async fn execute_attacks(
        &self,
        specs: &[AttackSpec],
        scope: &ScopeGuard,
    ) -> Vec<AttackResult> {
        let mut results = Vec::with_capacity(specs.len());
        for spec in specs {
            match self.execute_single(spec, scope).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!(
                        "Attack execution skipped for {} {}: {:#}",
                        spec.method, spec.url, e
                    );
                }
            }
        }
        results
    }

    async fn execute_single(
        &self,
        spec: &AttackSpec,
        scope: &ScopeGuard,
    ) -> anyhow::Result<AttackResult> {
        let method_upper = spec.method.to_uppercase();

        if !ALLOWED_METHODS.contains(&method_upper.as_str()) {
            anyhow::bail!(
                "HTTP method '{}' not supported for LLM attacks (supported: GET, POST, HEAD, OPTIONS)",
                method_upper
            );
        }

        if !scope.is_in_scope(&spec.url) {
            anyhow::bail!("URL out of scope: {}", spec.url);
        }

        debug!("Executing LLM attack: {} {}", method_upper, spec.url);

        // Build extra headers slice from the spec's header map
        let header_pairs: Vec<(String, String)> = spec.headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let extra_headers: Vec<(&str, &str)> = header_pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let start = std::time::Instant::now();

        let response = match method_upper.as_str() {
            "GET" => self.client.get_with_headers(&spec.url, &extra_headers).await?,
            "HEAD" => self.client.head(&spec.url).await?,
            "OPTIONS" => self.client.options(&spec.url).await?,
            "POST" => {
                let body = spec.body.as_deref().unwrap_or("");
                if spec.content_type.contains("json") {
                    self.client.post_json(&spec.url, body).await?
                } else {
                    self.client.post(&spec.url, body).await?
                }
            }
            _ => unreachable!("method already validated above"),
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;

        let body_snippet = if response.body.len() > MAX_EVIDENCE_SNIPPET {
            format!("{}...[truncated]", &response.body[..MAX_EVIDENCE_SNIPPET])
        } else {
            response.body.clone()
        };

        let confirmed = check_indicator(&spec.success_indicator, &response);

        debug!(
            "Attack result: {} {} -> status={}, confirmed={}",
            method_upper, spec.url, response.status, confirmed
        );

        Ok(AttackResult {
            spec: spec.clone(),
            response_status: response.status,
            response_body_snippet: body_snippet,
            confirmed,
            elapsed_ms,
        })
    }
}

/// Evaluate the LLM's success indicator against the actual HTTP response.
fn check_indicator(
    indicator: &SuccessIndicator,
    response: &crate::network::http::HttpResponse,
) -> bool {
    match indicator {
        SuccessIndicator::BodyContains { pattern } => response.body.contains(pattern.as_str()),
        SuccessIndicator::StatusCode { code } => response.status == *code,
        SuccessIndicator::HeaderContains { header, pattern } => response
            .headers
            .get(&header.to_lowercase())
            .map(|v| v.contains(pattern.as_str()))
            .unwrap_or(false),
        SuccessIndicator::BodyRegex { pattern } => match regex::Regex::new(pattern) {
            Ok(re) => re.is_match(&response.body),
            Err(e) => {
                warn!("Invalid regex from LLM '{}': {}", pattern, e);
                false
            }
        },
    }
}
