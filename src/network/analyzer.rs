use anyhow::Result;
use futures::future::{join_all, select_ok};
use regex::Regex;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};

use crate::core::scanner::{Finding, FindingCategory, ScanContext, Severity};
use crate::network::crawler::DiscoveredForm;
use crate::network::evasion::{self, EvasionStrategy};
use crate::network::http::{HttpClient, HttpResponse};
use crate::network::scope::ScopeGuard;

// ─────────────────────────────────────────────────────────────────────────────
// Static data — zero-alloc at search time
// ─────────────────────────────────────────────────────────────────────────────

/// SQL error signatures (lowercase bytes)
static SQL_ERROR_SIGS: &[&[u8]] = &[
    b"you have an error in your sql syntax",
    b"unclosed quotation mark",
    b"quoted string not properly terminated",
    b"pg_query()",
    b"sqlstate",
    b"ora-01756",
    b"microsoft ole db provider",
    b"odbc sql server driver",
    b"mysql_num_rows()",
    b"mysql_fetch_array()",
    b"supplied argument is not a valid mysql",
    b"org.postgresql.util.psqlexception",
    b"unterminated string",
    b"syntax error at or near",
];

/// Error-based + Union + simple boolean payloads
static SQL_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "1' OR '1'='1",
    "1\"OR\"1\"=\"1",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1 OR 1=1--",
    "' OR ''='",
];

/// Time-based blind SQLi payloads (expect response time significantly above baseline)
static SQL_TIME_PAYLOADS: &[&str] = &[
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
];

/// Fixed delay expected from SLEEP(5) payloads (ms)
const TIME_INJECT_DELAY_MS: u64 = 4000;

/// Path traversal payloads — PortSwigger labs + CTF bypass techniques
static TRAVERSAL_PAYLOADS: &[&str] = &[
    // Basic
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    // Recursive strip bypass (....// → ../ after single strip)
    "....//....//....//etc/passwd",
    // URL-encoding
    "..%2f..%2f..%2fetc%2fpasswd",
    // Double URL-encoding (PortSwigger lab: "double URL-encode the ../ sequence")
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    // Null-byte bypass (PortSwigger lab: "null byte bypass")
    "../../../etc/passwd%00.png",
    "../../../etc/passwd%00.jpg",
    // Absolute path (PortSwigger lab: "absolute path bypass")
    "/etc/passwd",
    // Dot-segment with trailing slash obfuscation
    "..%c0%af..%c0%afetc/passwd",
    // UTF-8 overlong encoding
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    // Mixed encoding
    "..%252f..%252fetc/passwd",
    // Windows targets
    "..\\..\\..\\windows\\system.ini",
    "..%5c..%5c..%5cwindows%5csystem.ini",
];

static TRAVERSAL_SIGS: &[&[u8]] = &[
    b"root:x:0:0:",
    b"daemon:x:",
    b"bin:x:",
    b"nobody:x:",
    b"[boot loader]",
    b"[fonts]",
    b"; for 16-bit app support",
    b"[extensions]",
    // /etc/hostname or /proc patterns
    b"PRETTY_NAME=",
];

/// Command injection payloads — echo-based (signature in response body)
static CMDI_ECHO_PAYLOADS: &[(&str, &[u8])] = &[
    (";echo SENTINEL_CMDI_7f3a", b"SENTINEL_CMDI_7f3a"),
    ("|echo SENTINEL_CMDI_7f3a", b"SENTINEL_CMDI_7f3a"),
    ("$(echo SENTINEL_CMDI_7f3a)", b"SENTINEL_CMDI_7f3a"),
    ("`echo SENTINEL_CMDI_7f3a`", b"SENTINEL_CMDI_7f3a"),
];

/// Command injection — time-based (expect >= 4500ms)
static CMDI_TIME_PAYLOADS: &[&str] = &[
    ";sleep 5",
    "|sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
];

/// SSTI payloads: (payload_string, expected_result_in_body)
/// Uses uncommon multiplication results (e.g., 913*773=705649) to avoid
/// false positives from numbers that appear naturally in page content.
/// Covers Jinja2, Twig, ERB, FreeMarker, Pebble, Thymeleaf, Mako, Smarty
static SSTI_PAYLOADS: &[(&str, &str)] = &[
    // Jinja2 / Twig / Nunjucks — {{913*773}} → 705649
    ("{{913*773}}", "705649"),
    // Jinja2 string repeat — {{913*'7'}} → "7" repeated 913 times
    ("{{913*'7'}}", "7777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"),
    // ERB (Ruby) — <%=913*773%> → 705649
    ("<%=913*773%>", "705649"),
    // FreeMarker / Mako — ${913*773} → 705649
    ("${913*773}", "705649"),
    // Smarty — {913*773} → 705649
    ("{913*773}", "705649"),
    // Thymeleaf (Spring) — [[${913*773}]] → 705649
    ("[[${913*773}]]", "705649"),
];

/// SSTI parameter names commonly used in template-rendering endpoints
static SSTI_PARAMS: &[&str] = &[
    "message", "name", "template", "content", "text", "body",
    "title", "comment", "desc", "greeting", "bio", "value",
];

/// CRLF injection payloads: (payload, header name to look for in response)
static CRLF_PAYLOADS: &[(&str, &str)] = &[
    ("%0d%0aX-Injected:sentinel", "x-injected"),
    ("%0d%0aSet-Cookie:sentinel_crlf=1", "sentinel_crlf"),
];

static REDIRECT_PARAMS: &[&str] = &[
    "redirect", "url", "next", "return", "goto", "continue", "dest",
];

static BYPASS_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For",           "127.0.0.1"),
    ("X-Original-URL",            "/"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host",          "localhost"),
    ("X-Real-IP",                 "127.0.0.1"),
];

/// Debug/info headers that shouldn't be exposed in production
static DEBUG_HEADERS: &[&str] = &[
    "x-debug-token",
    "x-debug-token-link",
    "x-debugging",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-request-id",
];

/// Dangerous HTTP methods
static DANGEROUS_METHODS: &[&str] = &["TRACE", "PUT", "DELETE"];

/// Mixed content regex (compiled once)
static MIXED_CONTENT_RE: OnceLock<Regex> = OnceLock::new();

/// Common parameter names to probe on param-less URLs
static COMMON_PARAMS: &[&str] = &[
    "id", "q", "search", "query", "page", "file", "path",
    "name", "user", "cmd", "url", "input", "data", "lang",
];

/// Regexes for body pattern analysis
static COMMENT_RE: OnceLock<Regex> = OnceLock::new();
static INTERNAL_IP_RE: OnceLock<Regex> = OnceLock::new();
static HIDDEN_INPUT_RE: OnceLock<Regex> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// ResponseAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

pub struct ResponseAnalyzer {
    ctx: ScanContext,
    client: HttpClient,
    scope: ScopeGuard,
}

impl ResponseAnalyzer {
    pub fn new(ctx: ScanContext, client: HttpClient, scope: ScopeGuard) -> Self {
        MIXED_CONTENT_RE.get_or_init(|| {
            Regex::new(r#"(?:src|href|action)\s*=\s*["']http://"#).unwrap()
        });
        COMMENT_RE.get_or_init(|| Regex::new(r"(?s)<!--(.*?)-->").unwrap());
        INTERNAL_IP_RE.get_or_init(|| {
            Regex::new(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            )
            .unwrap()
        });
        HIDDEN_INPUT_RE.get_or_init(|| {
            Regex::new(r#"(?i)<input[^>]*type\s*=\s*["']hidden["'][^>]*>"#).unwrap()
        });
        Self { ctx, client, scope }
    }

    pub async fn run(
        &self,
        target: &str,
        discovered_urls: &[String],
        forms: &[DiscoveredForm],
    ) -> Result<Vec<Finding>> {
        if !self.scope.is_in_scope(target) {
            warn!("Target {} is out of scope, skipping", target);
            return Ok(vec![]);
        }
        debug!(
            "Analyzer running against {} (timeout={}s, +{} urls, +{} forms)",
            target,
            self.ctx.config.timeout_secs,
            discovered_urls.len(),
            forms.len()
        );

        // ── Phase A: passive checks on base response (0 extra requests) ─
        let base_resp = self.client.get(target).await?;

        let mut findings = Vec::new();
        findings.extend(check_security_headers(&base_resp, target));
        findings.extend(check_cors(&base_resp, target));
        findings.extend(check_cookies(&base_resp, target));
        findings.extend(check_mixed_content(&base_resp, target));
        findings.extend(check_info_disclosure(&base_resp, target));
        findings.extend(check_body_patterns(&base_resp, target));

        // ── Phase B: active injection on target + discovered URLs ────────
        // Collect all URLs for injection testing (cap at 20)
        let mut injection_urls: Vec<String> = vec![target.to_string()];
        injection_urls.extend(discovered_urls.iter().take(19).cloned());

        let (inject_results, param_probe_results) = tokio::join!(
            self.check_injections_multi(&injection_urls, base_resp.elapsed_ms),
            self.probe_common_params(&injection_urls),
        );
        findings.extend(inject_results?);
        findings.extend(param_probe_results?);

        // ── Phase B2: form POST/GET injection (parallel) ─────────────────
        let form_tasks: Vec<_> = forms.iter().take(10).map(|form| {
            self.check_form_injection(form)
        }).collect();
        let form_results = join_all(form_tasks).await;
        for result in form_results {
            match result {
                Ok(f) => findings.extend(f),
                Err(e) => warn!("Form injection error: {}", e),
            }
        }

        // ── Phase C: special requests ────────────────────────────────────
        findings.extend(self.check_http_methods(target).await?);

        if base_resp.status == 403 {
            if let Ok(Some(bypassed)) = try_403_bypass(&self.client, target).await {
                let mut f = Finding::new(
                    Severity::Medium,
                    FindingCategory::Custom,
                    "403 Bypass Successful",
                    format!(
                        "Access control bypassed — response status {} instead of 403",
                        bypassed.status
                    ),
                    target.to_string(),
                );
                f.remediation = Some(
                    "Enforce access control at application layer, not just middleware".to_string(),
                );
                findings.push(f);
            }
        }

        Ok(findings)
    }

    /// Run injection checks (SQLi/Traversal/CMDi/CRLF/Redirect) on multiple URLs
    ///
    /// `target_baseline_ms` — elapsed_ms from the initial base_resp GET on the
    /// first URL (target).  Re-used to avoid a duplicate baseline request (①).
    async fn check_injections_multi(
        &self,
        urls: &[String],
        target_baseline_ms: u64,
    ) -> Result<Vec<Finding>> {
        // Build one future per URL with query params; drive all concurrently.
        let url_tasks: Vec<_> = urls
            .iter()
            .enumerate()
            .filter(|(_, url)| {
                url::Url::parse(url)
                    .map(|p| p.query_pairs().count() > 0)
                    .unwrap_or(false)
            })
            .map(|(idx, url)| {
                let self_ = self; // &Self is Copy
                let url = url.clone();
                async move {
                    let baseline_ms = if idx == 0 {
                        target_baseline_ms
                    } else {
                        match self_.client.get(&url).await {
                            Ok(resp) => resp.elapsed_ms,
                            Err(_) => 500,
                        }
                    };
                    let (sqli, traversal, cmdi, crlf, redirect, ssti) = tokio::join!(
                        self_.check_sqli(&url, baseline_ms),
                        self_.check_path_traversal(&url),
                        self_.check_cmdi(&url, baseline_ms),
                        self_.check_crlf(&url),
                        self_.check_open_redirect(&url),
                        self_.check_ssti(&url),
                    );
                    let mut v: Vec<Finding> = Vec::new();
                    if let Ok(f) = sqli      { v.extend(f); }
                    if let Ok(f) = traversal { v.extend(f); }
                    if let Ok(f) = cmdi      { v.extend(f); }
                    if let Ok(f) = crlf      { v.extend(f); }
                    if let Ok(f) = redirect  { v.extend(f); }
                    if let Ok(f) = ssti      { v.extend(f); }
                    v
                }
            })
            .collect();

        let results = join_all(url_tasks).await;
        Ok(results.into_iter().flatten().collect())
    }

    /// Probe common parameter names on param-less URLs
    async fn probe_common_params(&self, urls: &[String]) -> Result<Vec<Finding>> {
        let paramless: Vec<String> = urls
            .iter()
            .filter(|u| {
                url::Url::parse(u)
                    .map(|p| p.query_pairs().count() == 0)
                    .unwrap_or(false)
            })
            .take(5)
            .cloned()
            .collect();

        // SQLi + traversal: one task per (url × common_param), all concurrent
        let mut param_tasks: Vec<_> = Vec::new();
        for url in &paramless {
            let base = url.trim_end_matches('/').to_string();
            for &param in COMMON_PARAMS {
                let client = self.client.clone();
                let scope  = self.scope.clone();
                let base   = base.clone();
                param_tasks.push(async move {
                    let mut v: Vec<Finding> = Vec::new();

                    // SQLi probe: single quote
                    let sqli_url = format!("{}?{}='", base, param);
                    if scope.is_in_scope(&sqli_url) {
                        if let Ok(resp) = client.get(&sqli_url).await {
                            let body_lower: Vec<u8> = resp.body.as_bytes().iter()
                                .map(|b| b.to_ascii_lowercase()).collect();
                            for sig in SQL_ERROR_SIGS {
                                if memmem_find_lower(&body_lower, sig) {
                                    let mut f = Finding::new(
                                        Severity::High,
                                        FindingCategory::SqlInjection,
                                        format!("SQLi via discovered parameter '{}'", param),
                                        format!(
                                            "SQL error '{}' with payload \"'\" on probed param '{}'",
                                            std::str::from_utf8(sig).unwrap_or("?"),
                                            param
                                        ),
                                        sqli_url.clone(),
                                    );
                                    f.evidence    = Some(format!("Param: {}, Payload: '", param));
                                    f.remediation = Some("Use parameterized queries / prepared statements".to_string());
                                    v.push(f);
                                    break;
                                }
                            }
                        }
                    }

                    // Path traversal probe
                    let trav_url = format!("{}?{}=../../etc/passwd", base, param);
                    if let Ok(resp) = client.get(&trav_url).await {
                        let body_lower: Vec<u8> = resp.body.as_bytes().iter()
                            .map(|b| b.to_ascii_lowercase()).collect();
                        for sig in TRAVERSAL_SIGS {
                            if memmem_find_lower(&body_lower, sig) {
                                let mut f = Finding::new(
                                    Severity::High,
                                    FindingCategory::DirectoryTraversal,
                                    format!("Path Traversal via discovered parameter '{}'", param),
                                    format!(
                                        "File content found with traversal payload on probed param '{}'",
                                        param
                                    ),
                                    trav_url.clone(),
                                );
                                f.evidence    = Some(format!("Param: {}, Payload: ../../etc/passwd", param));
                                f.remediation = Some("Validate and sanitize file paths; use allowlists".to_string());
                                v.push(f);
                                break;
                            }
                        }
                    }

                    v
                });
            }
        }

        // SSTI: one task per (url × ssti_param), payloads tried sequentially
        // so only the first matching payload fires (preserves original break behaviour)
        let mut ssti_tasks: Vec<_> = Vec::new();
        for url in &paramless {
            let base = url.trim_end_matches('/').to_string();
            for &param in SSTI_PARAMS {
                let client = self.client.clone();
                let scope  = self.scope.clone();
                let base   = base.clone();
                ssti_tasks.push(async move {
                    for &(payload, expected) in SSTI_PAYLOADS {
                        let test_url = format!("{}?{}={}", base, param, payload);
                        if !scope.is_in_scope(&test_url) { continue; }
                        if let Ok(resp) = client.get(&test_url).await {
                            if resp.body.contains(expected) && !resp.body.contains(payload) {
                                let mut f = Finding::new(
                                    Severity::Critical,
                                    FindingCategory::Custom,
                                    format!("SSTI via discovered parameter '{}'", param),
                                    format!(
                                        "Template expression '{}' evaluated to '{}' on probed param '{}'",
                                        payload, expected, param
                                    ),
                                    test_url,
                                );
                                f.evidence    = Some(format!("Param: {}, Payload: {} → {}", param, payload, expected));
                                f.remediation = Some("Never render user input in templates. Use sandboxed engines.".to_string());
                                return Some(f);
                            }
                        }
                    }
                    None
                });
            }
        }

        let mut findings: Vec<Finding> = Vec::new();
        for v in join_all(param_tasks).await {
            findings.extend(v);
        }
        for opt in join_all(ssti_tasks).await {
            if let Some(f) = opt { findings.push(f); }
        }

        Ok(findings)
    }

    /// Test form fields for injection vulnerabilities
    async fn check_form_injection(&self, form: &DiscoveredForm) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let sqli_payloads = &["'", "\"", "1' OR '1'='1"];

        for (field_idx, (field_name, _)) in form.fields.iter().enumerate() {
            // SQLi test
            for payload in sqli_payloads {
                let body = build_form_body(&form.fields, field_idx, payload);

                let resp = if form.method == "POST" {
                    self.client.post(&form.action, &body).await
                } else {
                    let url = format!("{}?{}", form.action.trim_end_matches('/'), body);
                    self.client.get(&url).await
                };

                if let Ok(resp) = resp {
                    let body_bytes = resp.body.as_bytes();
                    for sig in SQL_ERROR_SIGS {
                        if memmem_find_icase(body_bytes, sig) {
                            let mut f = Finding::new(
                                Severity::High,
                                FindingCategory::SqlInjection,
                                format!(
                                    "SQLi in form field '{}' ({} {})",
                                    field_name, form.method, form.action
                                ),
                                format!(
                                    "SQL error '{}' found when injecting '{}' into form field '{}'",
                                    std::str::from_utf8(sig).unwrap_or("?"),
                                    payload,
                                    field_name
                                ),
                                form.action.clone(),
                            );
                            f.evidence = Some(format!(
                                "Method: {}, Field: {}, Payload: {}",
                                form.method, field_name, payload
                            ));
                            f.remediation = Some(
                                "Use parameterized queries / prepared statements".to_string(),
                            );
                            findings.push(f);
                            return Ok(findings); // one finding per form
                        }
                    }

                    // Time-based blind (conservative threshold for forms)
                    if resp.elapsed_ms >= (1000 + TIME_INJECT_DELAY_MS) {
                        let mut f = Finding::new(
                            Severity::High,
                            FindingCategory::SqlInjection,
                            format!(
                                "Blind SQLi (time-based) in form field '{}' ({} {})",
                                field_name, form.method, form.action
                            ),
                            format!(
                                "Response delayed {}ms with payload '{}' in field '{}'",
                                resp.elapsed_ms, payload, field_name
                            ),
                            form.action.clone(),
                        );
                        f.evidence = Some(format!(
                            "Field: {}, Payload: {}, Elapsed: {}ms",
                            field_name, payload, resp.elapsed_ms
                        ));
                        f.remediation =
                            Some("Use parameterized queries / prepared statements".to_string());
                        findings.push(f);
                        return Ok(findings);
                    }
                }
            }

            // CMDi test on form fields
            for (payload, marker) in CMDI_ECHO_PAYLOADS {
                let body = build_form_body(&form.fields, field_idx, payload);
                let resp = if form.method == "POST" {
                    self.client.post(&form.action, &body).await
                } else {
                    let url = format!("{}?{}", form.action.trim_end_matches('/'), body);
                    self.client.get(&url).await
                };
                if let Ok(resp) = resp {
                    if memmem_find_icase(resp.body.as_bytes(), marker) {
                        let mut f = Finding::new(
                            Severity::Critical,
                            FindingCategory::CommandInjection,
                            format!(
                                "Command Injection in form field '{}' ({} {})",
                                field_name, form.method, form.action
                            ),
                            format!(
                                "Echo marker reflected when injecting into form field '{}'",
                                field_name
                            ),
                            form.action.clone(),
                        );
                        f.evidence = Some(format!(
                            "Method: {}, Field: {}, Payload: {}",
                            form.method, field_name, payload
                        ));
                        f.remediation = Some(
                            "Never pass user input to shell commands; use safe APIs".to_string(),
                        );
                        findings.push(f);
                        return Ok(findings);
                    }
                }
            }
        }

        Ok(findings)
    }

    // ── SQLi: error-based + time-based blind ────────────────────────────
    async fn check_sqli(&self, url: &str, baseline_ms: u64) -> Result<Vec<Finding>> {
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]),
        };
        let original_query: Arc<Vec<(String, String)>> = Arc::new(
            parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        );
        if original_query.is_empty() {
            return Ok(vec![]);
        }

        let tasks: Vec<_> = original_query
            .iter()
            .map(|(param_name, _)| {
                let client     = self.client.clone();
                let scope      = self.scope.clone();
                let param_name = param_name.clone();
                let orig_query = Arc::clone(&original_query);
                let url_str    = url.to_string();
                let thorough = self.ctx.config.thorough;
                async move {
                    sqli_probe_param(client, scope, url_str, param_name, orig_query, baseline_ms, thorough).await
                }
            })
            .collect();

        let results = join_all(tasks).await;
        Ok(results.into_iter().flatten().collect())
    }

    // ── Path Traversal ──────────────────────────────────────────────────
    async fn check_path_traversal(&self, url: &str) -> Result<Vec<Finding>> {
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]),
        };
        let original_query: Arc<Vec<(String, String)>> = Arc::new(
            parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        );
        if original_query.is_empty() {
            return Ok(vec![]);
        }

        let tasks: Vec<_> = original_query
            .iter()
            .map(|(param_name, _)| {
                let client     = self.client.clone();
                let scope      = self.scope.clone();
                let param_name = param_name.clone();
                let orig_query = Arc::clone(&original_query);
                let url_str    = url.to_string();
                async move {
                    traversal_probe_param(client, scope, url_str, param_name, orig_query).await
                }
            })
            .collect();

        let results = join_all(tasks).await;
        Ok(results.into_iter().flatten().collect())
    }

    // ── Command Injection ───────────────────────────────────────────────
    async fn check_cmdi(&self, url: &str, baseline_ms: u64) -> Result<Vec<Finding>> {
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]),
        };
        let original_query: Arc<Vec<(String, String)>> = Arc::new(
            parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        );
        if original_query.is_empty() {
            return Ok(vec![]);
        }

        let tasks: Vec<_> = original_query
            .iter()
            .map(|(param_name, _)| {
                let client     = self.client.clone();
                let scope      = self.scope.clone();
                let param_name = param_name.clone();
                let orig_query = Arc::clone(&original_query);
                let url_str    = url.to_string();
                async move {
                    cmdi_probe_param(client, scope, url_str, param_name, orig_query, baseline_ms).await
                }
            })
            .collect();

        let results = join_all(tasks).await;
        Ok(results.into_iter().flatten().collect())
    }

    // ── SSTI (Server-Side Template Injection) ──────────────────────────
    // Covers: Jinja2, Twig, ERB, FreeMarker, Pebble, Smarty, Mako, Thymeleaf
    // Matches HTB Trial By Fire, PortSwigger SSTI labs, DefCamp Rocket
    async fn check_ssti(&self, url: &str) -> Result<Vec<Finding>> {
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]),
        };
        let original_query: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if original_query.is_empty() {
            return Ok(vec![]);
        }

        let mut findings = Vec::new();

        for (param_name, _) in &original_query {
            for (payload, expected) in SSTI_PAYLOADS {
                let Some(test_url) = inject_param(url, param_name, payload, &original_query, false)
                else { continue };
                if !self.scope.is_in_scope(&test_url) { continue; }

                if let Ok(resp) = self.client.get(&test_url).await {
                    if resp.body.contains(expected) {
                        // Verify it's real SSTI, not just echoed input
                        // The expected value (e.g. "49") should appear but the raw payload should not
                        let is_evaluated = !resp.body.contains(payload);
                        if is_evaluated {
                            let mut f = Finding::new(
                                Severity::Critical,
                                FindingCategory::Custom,
                                format!("SSTI in parameter '{}' (template evaluated)", param_name),
                                format!(
                                    "Template expression '{}' evaluated to '{}' — confirmed server-side template injection",
                                    payload, expected
                                ),
                                test_url,
                            );
                            f.evidence = Some(format!("Payload: {} → Response contains: {}", payload, expected));
                            f.remediation = Some(
                                "Never render user input directly in templates. Use sandboxed template engines or escape all input.".to_string(),
                            );
                            findings.push(f);
                            return Ok(findings);
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    // ── CRLF Injection ──────────────────────────────────────────────────
    async fn check_crlf(&self, url: &str) -> Result<Vec<Finding>> {
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok(vec![]),
        };
        let original_query: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if original_query.is_empty() {
            return Ok(vec![]);
        }

        let mut findings = Vec::new();
        let mut parsed_mut = parsed;

        for (param_name, _) in &original_query {
            for (payload, expected_header) in CRLF_PAYLOADS {
                let mut new_query = original_query.clone();
                for (k, v) in &mut new_query {
                    if k == param_name {
                        v.push_str(payload);
                    }
                }
                parsed_mut.query_pairs_mut().clear();
                for (k, v) in &new_query {
                    parsed_mut.query_pairs_mut().append_pair(k, v);
                }

                let test_url = parsed_mut.as_str().to_string();
                if !self.scope.is_in_scope(&test_url) {
                    continue;
                }

                if let Ok(resp) = self.client.get(&test_url).await {
                    // Case-insensitive header check (headers stored lowercase by reqwest,
                    // but check contains() for injected header fragments too)
                    if resp.headers.keys().any(|k| k.to_lowercase().contains(expected_header)) {
                        let mut f = Finding::new(
                            Severity::High,
                            FindingCategory::CrlfInjection,
                            format!("CRLF Injection in parameter '{}'", param_name),
                            format!("Injected header '{}' appeared in response", expected_header),
                            test_url,
                        );
                        f.evidence = Some(format!("Payload: {}", payload));
                        f.remediation = Some(
                            "Sanitize CR/LF characters (\\r\\n) from user input before use in HTTP headers".to_string(),
                        );
                        findings.push(f);
                        break;
                    }
                }
            }
        }

        Ok(findings)
    }

    // ── Open Redirect ───────────────────────────────────────────────────
    async fn check_open_redirect(&self, url: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let payload = "https://evil-example.com/";

        if let Ok(mut parsed) = url::Url::parse(url) {
            let original_query: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for (param_name, _) in &original_query {
                if !REDIRECT_PARAMS
                    .iter()
                    .any(|&p| param_name.to_lowercase().contains(p))
                {
                    continue;
                }

                let mut new_query = original_query.clone();
                for (k, v) in &mut new_query {
                    if k == param_name {
                        *v = payload.to_string();
                    }
                }
                parsed.query_pairs_mut().clear();
                for (k, v) in &new_query {
                    parsed.query_pairs_mut().append_pair(k, v);
                }

                let test_url = parsed.as_str().to_string();
                // Use no-redirect to inspect Location header directly
                // (avoids actually navigating to evil-example.com)
                if let Ok(resp) = self.client.get_no_redirect(&test_url).await {
                    let is_redirect = (300..400).contains(&resp.status);
                    let location_evil = resp.headers
                        .get("location")
                        .map(|loc| loc.contains("evil-example.com"))
                        .unwrap_or(false);
                    // Also check if body/url contains it (meta refresh, JS redirect)
                    let body_evil = resp.body.contains("evil-example.com");
                    if (is_redirect && location_evil) || body_evil {
                        findings.push(Finding::new(
                            Severity::Medium,
                            FindingCategory::Custom,
                            format!("Open Redirect via parameter '{}'", param_name),
                            "Application redirects to arbitrary external URL".to_string(),
                            url.to_string(),
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }

    // ── HTTP Method Check ───────────────────────────────────────────────
    async fn check_http_methods(&self, url: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(resp) = self.client.options(url).await {
            if let Some(allow) = resp.headers.get("allow") {
                let allow_upper = allow.to_uppercase();
                for method in DANGEROUS_METHODS {
                    if allow_upper.contains(method) {
                        let mut f = Finding::new(
                            Severity::Medium,
                            FindingCategory::InformationDisclosure,
                            format!("Dangerous HTTP method enabled: {}", method),
                            format!("OPTIONS response reveals '{}' is allowed", method),
                            url.to_string(),
                        );
                        f.remediation = Some(format!("Disable {} method if not required", method));
                        findings.push(f);
                    }
                }
            }
        }

        Ok(findings)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Passive checks (free functions, no extra HTTP requests)
// ─────────────────────────────────────────────────────────────────────────────

fn check_security_headers(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = &resp.headers;

    let required = &[
        ("x-frame-options",           "X-Frame-Options missing (Clickjacking risk)"),
        ("x-content-type-options",    "X-Content-Type-Options missing (MIME sniffing risk)"),
        ("strict-transport-security", "HSTS header missing"),
        ("content-security-policy",   "Content-Security-Policy missing"),
        ("referrer-policy",           "Referrer-Policy missing (token leak via Referer header)"),
        ("permissions-policy",        "Permissions-Policy missing (browser feature restriction)"),
    ];

    for (header, desc) in required {
        if !headers.contains_key(*header) {
            let mut f = Finding::new(
                Severity::Low,
                FindingCategory::MissingHeader,
                format!("Missing header: {}", header.to_uppercase()),
                desc.to_string(),
                url.to_string(),
            );
            f.remediation = Some(format!("Add '{}' response header", header));
            findings.push(f);
        }
    }

    if url.starts_with("https://") {
        if let Some(hsts) = headers.get("strict-transport-security") {
            if !hsts.contains("includeSubDomains") {
                findings.push(Finding::new(
                    Severity::Low,
                    FindingCategory::MissingHeader,
                    "HSTS missing includeSubDomains".to_string(),
                    "HSTS header does not include subdomains".to_string(),
                    url.to_string(),
                ));
            }
            // Check max-age >= 31536000 (1 year)
            if let Some(max_age) = hsts
                .split(';')
                .find_map(|p| p.trim().strip_prefix("max-age="))
            {
                if let Ok(val) = max_age.trim().parse::<u64>() {
                    if val < 31536000 {
                        findings.push(Finding::new(
                            Severity::Low,
                            FindingCategory::MissingHeader,
                            "HSTS max-age too short".to_string(),
                            format!("max-age={} is less than 1 year (31536000)", val),
                            url.to_string(),
                        ));
                    }
                }
            }
        }
    }

    findings
}

fn check_cors(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = &resp.headers;

    if let Some(origin) = headers.get("access-control-allow-origin") {
        if origin == "*" {
            let creds = headers
                .get("access-control-allow-credentials")
                .map(|v| v == "true")
                .unwrap_or(false);

            if creds {
                let mut f = Finding::new(
                    Severity::High,
                    FindingCategory::Cors,
                    "CORS: wildcard origin with credentials",
                    "Access-Control-Allow-Origin: * combined with Allow-Credentials: true allows credential theft".to_string(),
                    url.to_string(),
                );
                f.remediation = Some("Never combine wildcard origin with credentials; whitelist specific origins".to_string());
                findings.push(f);
            } else {
                let mut f = Finding::new(
                    Severity::Medium,
                    FindingCategory::Cors,
                    "CORS: wildcard origin (*)",
                    "Access-Control-Allow-Origin: * allows any site to read responses".to_string(),
                    url.to_string(),
                );
                f.remediation = Some("Restrict to specific trusted origins".to_string());
                findings.push(f);
            }
        }
    }

    findings
}

fn check_cookies(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (header_name, header_value) in &resp.headers {
        if header_name != "set-cookie" {
            continue;
        }

        let lower       = header_value.to_lowercase();
        let cookie_name = header_value.split('=').next().unwrap_or("?").trim().to_string();

        if !lower.contains("httponly") {
            findings.push(Finding::new(
                Severity::Medium,
                FindingCategory::InsecureCookie,
                format!("Cookie '{}' missing HttpOnly flag", cookie_name),
                "Cookie accessible via JavaScript (XSS risk)".to_string(),
                url.to_string(),
            ));
        }
        if url.starts_with("https://") && !lower.contains("secure") {
            findings.push(Finding::new(
                Severity::Medium,
                FindingCategory::InsecureCookie,
                format!("Cookie '{}' missing Secure flag", cookie_name),
                "Cookie may be sent over plain HTTP".to_string(),
                url.to_string(),
            ));
        }
        if !lower.contains("samesite") {
            findings.push(Finding::new(
                Severity::Low,
                FindingCategory::InsecureCookie,
                format!("Cookie '{}' missing SameSite attribute", cookie_name),
                "Cookie may be sent in cross-site requests (CSRF risk)".to_string(),
                url.to_string(),
            ));
        }
    }

    findings
}

fn check_mixed_content(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !url.starts_with("https://") {
        return findings;
    }

    let re = MIXED_CONTENT_RE.get().expect("initialized in new()");
    if re.is_match(&resp.body) {
        let mut f = Finding::new(
            Severity::Medium,
            FindingCategory::MissingHeader,
            "Mixed Content: HTTP resources on HTTPS page",
            "Page loads resources over insecure HTTP, undermining TLS".to_string(),
            url.to_string(),
        );
        f.remediation = Some("Use protocol-relative or HTTPS URLs for all resources".to_string());
        findings.push(f);
    }

    findings
}

fn check_info_disclosure(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = &resp.headers;

    // Check debug headers
    for header in DEBUG_HEADERS {
        if headers.contains_key(*header) {
            findings.push(Finding::new(
                Severity::Low,
                FindingCategory::InformationDisclosure,
                format!("Debug header exposed: {}", header),
                format!("Response contains '{}' header — debug information leak", header),
                url.to_string(),
            ));
        }
    }

    // Server header with detailed version
    if let Some(server) = headers.get("server") {
        if server.contains('/') {
            let mut f = Finding::new(
                Severity::Low,
                FindingCategory::InformationDisclosure,
                "Server version disclosed",
                format!("Server header reveals: {}", server),
                url.to_string(),
            );
            f.remediation = Some("Remove version info from Server header".to_string());
            findings.push(f);
        }
    }

    // X-Powered-By with version
    if let Some(xpb) = headers.get("x-powered-by") {
        let mut f = Finding::new(
            Severity::Low,
            FindingCategory::InformationDisclosure,
            "X-Powered-By header exposed",
            format!("X-Powered-By reveals: {}", xpb),
            url.to_string(),
        );
        f.remediation = Some("Remove X-Powered-By header".to_string());
        findings.push(f);
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Active probe functions (per-parameter, used with join_all)
// ─────────────────────────────────────────────────────────────────────────────

/// Inject a payload into a specific URL parameter and return the modified URL
fn inject_param(
    base_url: &str,
    param_name: &str,
    payload: &str,
    original_query: &[(String, String)],
    append: bool,
) -> Option<String> {
    let mut parsed = url::Url::parse(base_url).ok()?;
    let mut new_query: Vec<(String, String)> = original_query.to_vec();
    for (k, v) in &mut new_query {
        if k == param_name {
            if append {
                v.push_str(payload);
            } else {
                *v = payload.to_string();
            }
        }
    }
    parsed.query_pairs_mut().clear();
    for (k, v) in &new_query {
        parsed.query_pairs_mut().append_pair(k, v);
    }
    Some(parsed.as_str().to_string())
}

/// SQLi probe: error-based + time-based blind + WAF evasion variants
async fn sqli_probe_param(
    client: HttpClient,
    scope: ScopeGuard,
    url: String,
    param_name: String,
    original_query: Arc<Vec<(String, String)>>,
    baseline_ms: u64,
    thorough: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Error-based — with WAF evasion variants (fast or thorough)
    for payload in SQL_PAYLOADS {
        let variants = if thorough {
            evasion::generate_variants(payload)
        } else {
            evasion::generate_fast_variants(payload)
        };
        for (encoded_payload, strategy) in variants {
            let Some(test_url) = inject_param(&url, &param_name, &encoded_payload, &original_query, false)
            else { continue };
            if !scope.is_in_scope(&test_url) { continue; }

            if let Ok(resp) = client.get(&test_url).await {
                let body_lower: Vec<u8> = resp.body.as_bytes().iter().map(|b| b.to_ascii_lowercase()).collect();
                for sig in SQL_ERROR_SIGS {
                    if memmem_find_lower(&body_lower, sig) {
                        let evasion_note = if strategy != EvasionStrategy::None {
                            format!(" (WAF bypass: {:?})", strategy)
                        } else {
                            String::new()
                        };
                        debug!("SQLi signal at {} param={}{}", url, param_name, evasion_note);
                        let mut f = Finding::new(
                            Severity::High,
                            FindingCategory::SqlInjection,
                            format!("Potential SQLi in parameter '{}'", param_name),
                            format!(
                                "SQL error '{}' found with payload '{}'{}",
                                std::str::from_utf8(sig).unwrap_or("?"),
                                encoded_payload,
                                evasion_note,
                            ),
                            test_url,
                        );
                        f.evidence    = Some(format!("Payload: {}{}", encoded_payload, evasion_note));
                        f.remediation = Some("Use parameterized queries / prepared statements".to_string());
                        findings.push(f);
                        return findings; // one finding per param is enough
                    }
                }
            }
        }
    }

    // Time-based blind (only if error-based found nothing) — with evasion
    let time_threshold = baseline_ms + TIME_INJECT_DELAY_MS;
    for payload in SQL_TIME_PAYLOADS {
        let variants = if thorough {
            evasion::generate_variants(payload)
        } else {
            evasion::generate_fast_variants(payload)
        };
        for (encoded_payload, strategy) in variants {
            let Some(test_url) = inject_param(&url, &param_name, &encoded_payload, &original_query, false)
            else { continue };
            if !scope.is_in_scope(&test_url) { continue; }

            if let Ok(resp) = client.get(&test_url).await {
                if resp.elapsed_ms >= time_threshold {
                    let evasion_note = if strategy != EvasionStrategy::None {
                        format!(" (WAF bypass: {:?})", strategy)
                    } else {
                        String::new()
                    };
                    debug!("SQLi time-based at {} param={} ({}ms, baseline={}ms){}", url, param_name, resp.elapsed_ms, baseline_ms, evasion_note);
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::SqlInjection,
                        format!("Blind SQLi (time-based) in parameter '{}'", param_name),
                        format!(
                            "Response delayed {}ms (baseline {}ms + {}ms threshold) with payload '{}'{}",
                            resp.elapsed_ms, baseline_ms, TIME_INJECT_DELAY_MS, encoded_payload, evasion_note
                        ),
                        test_url,
                    );
                    f.evidence    = Some(format!("Payload: {} | Elapsed: {}ms | Baseline: {}ms{}", encoded_payload, resp.elapsed_ms, baseline_ms, evasion_note));
                    f.remediation = Some("Use parameterized queries / prepared statements".to_string());
                    findings.push(f);
                    return findings;
                }
            }
        }
    }

    findings
}

/// Path traversal probe
async fn traversal_probe_param(
    client: HttpClient,
    scope: ScopeGuard,
    url: String,
    param_name: String,
    original_query: Arc<Vec<(String, String)>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for payload in TRAVERSAL_PAYLOADS {
        let Some(test_url) = inject_param(&url, &param_name, payload, &original_query, false)
        else { continue };
        if !scope.is_in_scope(&test_url) { continue; }

        if let Ok(resp) = client.get(&test_url).await {
            let body_lower: Vec<u8> = resp.body.as_bytes().iter().map(|b| b.to_ascii_lowercase()).collect();
            for sig in TRAVERSAL_SIGS {
                if memmem_find_lower(&body_lower, sig) {
                    debug!("Path traversal at {} param={}", url, param_name);
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::DirectoryTraversal,
                        format!("Path Traversal in parameter '{}'", param_name),
                        format!(
                            "File content signature '{}' found with payload '{}'",
                            std::str::from_utf8(sig).unwrap_or("?"),
                            payload
                        ),
                        test_url,
                    );
                    f.evidence    = Some(format!("Payload: {}", payload));
                    f.remediation = Some("Validate and sanitize file paths; use allowlists instead of blocklists".to_string());
                    findings.push(f);
                    return findings;
                }
            }
        }
    }

    findings
}

/// Command injection probe: echo-based + time-based
async fn cmdi_probe_param(
    client: HttpClient,
    scope: ScopeGuard,
    url: String,
    param_name: String,
    original_query: Arc<Vec<(String, String)>>,
    baseline_ms: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Echo-based
    for (payload, marker) in CMDI_ECHO_PAYLOADS {
        let Some(test_url) = inject_param(&url, &param_name, payload, &original_query, true)
        else { continue };
        if !scope.is_in_scope(&test_url) { continue; }

        if let Ok(resp) = client.get(&test_url).await {
            if memmem_find_icase(resp.body.as_bytes(), marker) {
                debug!("CMDi echo at {} param={}", url, param_name);
                let mut f = Finding::new(
                    Severity::Critical,
                    FindingCategory::CommandInjection,
                    format!("Command Injection in parameter '{}'", param_name),
                    format!("Echo marker '{}' reflected in response", std::str::from_utf8(marker).unwrap_or("?")),
                    test_url,
                );
                f.evidence    = Some(format!("Payload: {}", payload));
                f.remediation = Some("Never pass user input to shell commands; use safe APIs".to_string());
                findings.push(f);
                return findings;
            }
        }
    }

    // Time-based
    let time_threshold = baseline_ms + TIME_INJECT_DELAY_MS;
    for payload in CMDI_TIME_PAYLOADS {
        let Some(test_url) = inject_param(&url, &param_name, payload, &original_query, true)
        else { continue };
        if !scope.is_in_scope(&test_url) { continue; }

        if let Ok(resp) = client.get(&test_url).await {
            if resp.elapsed_ms >= time_threshold {
                debug!("CMDi time-based at {} param={} ({}ms, baseline={}ms)", url, param_name, resp.elapsed_ms, baseline_ms);
                let mut f = Finding::new(
                    Severity::Critical,
                    FindingCategory::CommandInjection,
                    format!("Command Injection (time-based) in parameter '{}'", param_name),
                    format!("Response delayed {}ms (baseline {}ms) with payload '{}'", resp.elapsed_ms, baseline_ms, payload),
                    test_url,
                );
                f.evidence    = Some(format!("Payload: {} | Elapsed: {}ms | Baseline: {}ms", payload, resp.elapsed_ms, baseline_ms));
                f.remediation = Some("Never pass user input to shell commands; use safe APIs".to_string());
                findings.push(f);
                return findings;
            }
        }
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 403 Bypass: headers + path mutations (select_ok race)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn try_403_bypass(
    client: &HttpClient,
    url: &str,
) -> Result<Option<HttpResponse>> {
    type BoxFut = Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send>>;

    let mut futures: Vec<BoxFut> = Vec::new();

    // Header-based bypass
    for (k, v) in BYPASS_HEADERS {
        let client = client.clone();
        let url    = url.to_string();
        let k      = *k;
        let v      = *v;
        futures.push(Box::pin(async move {
            let resp = client.get_with_headers(&url, &[(k, v)]).await?;
            if resp.status != 403 { Ok(resp) } else { Err(anyhow::anyhow!("still 403")) }
        }));
    }

    // Path mutation bypass
    let path_mutations: Vec<String> = generate_path_mutations(url);
    for mutated_url in path_mutations {
        let client = client.clone();
        futures.push(Box::pin(async move {
            let resp = client.get(&mutated_url).await?;
            if resp.status != 403 { Ok(resp) } else { Err(anyhow::anyhow!("still 403")) }
        }));
    }

    if futures.is_empty() {
        return Ok(None);
    }

    match select_ok(futures).await {
        Ok((resp, _remaining)) => {
            debug!("403 bypass succeeded (status: {})", resp.status);
            Ok(Some(resp))
        }
        Err(_) => Ok(None),
    }
}

fn generate_path_mutations(url: &str) -> Vec<String> {
    let mut mutations = Vec::new();
    let Ok(parsed) = url::Url::parse(url) else { return mutations };
    let path = parsed.path().to_string();
    let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

    // Trailing slash
    if !path.ends_with('/') {
        mutations.push(format!("{}{}/", base, path));
    }
    // Double slash prefix
    mutations.push(format!("{}/{}", base, path));
    // Dot segment
    mutations.push(format!("{}{}./", base, path));
    // Case variation (capitalize first char after last /)
    if let Some(pos) = path.rfind('/') {
        let (prefix, suffix) = path.split_at(pos + 1);
        if let Some(first_char) = suffix.chars().next() {
            let toggled: String = std::iter::once(
                if first_char.is_lowercase() { first_char.to_uppercase().next().unwrap() }
                else { first_char.to_lowercase().next().unwrap() }
            ).chain(suffix.chars().skip(1)).collect();
            mutations.push(format!("{}{}{}", base, prefix, toggled));
        }
    }
    // URL-encoded path
    let encoded_path = path.replace('/', "%2f");
    mutations.push(format!("{}/{}", base, encoded_path.trim_start_matches("%2f")));

    mutations
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

/// Build a form-encoded body string, injecting payload at field_idx
fn build_form_body(fields: &[(String, String)], inject_idx: usize, payload: &str) -> String {
    fields
        .iter()
        .enumerate()
        .map(|(i, (name, value))| {
            let val = if i == inject_idx { payload } else { value.as_str() };
            format!("{}={}", simple_form_encode(name), simple_form_encode(val))
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal form-encoding: only escape characters that break form structure
fn simple_form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '+' => out.push_str("%2B"),
            '#' => out.push_str("%23"),
            ' ' => out.push('+'),
            _ => out.push(c),
        }
    }
    out
}

/// Passive: detect sensitive patterns in HTML body (no extra requests)
fn check_body_patterns(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let body = &resp.body;
    let body_lower = body.to_lowercase();

    // 1. HTML comments with sensitive keywords
    let comment_re = COMMENT_RE.get().expect("initialized in new()");
    let sensitive_words = [
        "password", "passwd", "secret", "api_key", "apikey", "api-key",
        "token", "todo", "fixme", "hack", "debug", "admin",
    ];
    for cap in comment_re.captures_iter(body) {
        let comment = cap.get(1).unwrap().as_str().to_lowercase();
        for word in &sensitive_words {
            if comment.contains(word) {
                let snippet = &cap[0];
                let truncated = if snippet.len() > 150 {
                    format!("{}...", &snippet[..150])
                } else {
                    snippet.to_string()
                };
                findings.push(Finding::new(
                    Severity::Low,
                    FindingCategory::InformationDisclosure,
                    format!("HTML comment contains '{}'", word),
                    format!("Sensitive keyword in comment: {}", truncated),
                    url.to_string(),
                ));
                break;
            }
        }
    }

    // 2. Hidden inputs with suspicious names
    let hidden_re = HIDDEN_INPUT_RE.get().expect("initialized in new()");
    for cap in hidden_re.captures_iter(body) {
        let input_lower = cap[0].to_lowercase();
        let suspicious = ["debug", "role", "is_admin", "isadmin", "privilege", "internal"];
        for keyword in &suspicious {
            if input_lower.contains(keyword) {
                findings.push(Finding::new(
                    Severity::Medium,
                    FindingCategory::InformationDisclosure,
                    format!("Suspicious hidden input: '{}'", keyword),
                    format!("Hidden field may expose internal state: {}", &cap[0]),
                    url.to_string(),
                ));
                break;
            }
        }
    }

    // 3. Internal IP addresses in body
    let ip_re = INTERNAL_IP_RE.get().expect("initialized in new()");
    if ip_re.is_match(body) {
        findings.push(Finding::new(
            Severity::Low,
            FindingCategory::InformationDisclosure,
            "Internal IP address in response body",
            "Response contains private IP address (10.x / 172.16-31.x / 192.168.x)",
            url.to_string(),
        ));
    }

    // 4. Error patterns in body (stack traces, debug output)
    let error_patterns: &[(&str, &str)] = &[
        ("traceback (most recent call last)", "Python traceback exposed"),
        ("exception in thread", "Java exception exposed"),
        ("fatal error:", "PHP fatal error exposed"),
        ("syntax error", "Syntax error message exposed"),
        ("unhandled exception", "Unhandled exception exposed"),
        ("debug mode is on", "Debug mode is enabled"),
        ("werkzeug debugger", "Werkzeug debugger is accessible"),
    ];
    for (pattern, desc) in error_patterns {
        if body_lower.contains(pattern) {
            findings.push(Finding::new(
                Severity::Medium,
                FindingCategory::InformationDisclosure,
                desc.to_string(),
                format!("Response body contains: '{}'", pattern),
                url.to_string(),
            ));
        }
    }

    findings
}

/// Case-insensitive byte search — SIMD-accelerated via `memchr::memmem`.
///
/// Converts haystack to lowercase in a stack buffer (up to 8 KB) or heap
/// (larger bodies), then uses `memchr::memmem::find()` which leverages
/// Two-Way / SIMD on x86_64 and aarch64.  Needle **must** already be lowercase.
fn memmem_find_icase(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    // For short haystacks, use the simple loop to avoid allocation
    if haystack.len() <= 8192 {
        // Stack-based lowercase conversion
        let mut buf = [0u8; 8192];
        let slice = &mut buf[..haystack.len()];
        for (dst, src) in slice.iter_mut().zip(haystack.iter()) {
            *dst = src.to_ascii_lowercase();
        }
        return memchr::memmem::find(slice, needle).is_some();
    }

    // For larger bodies, heap-allocate the lowercase copy
    let lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
    memchr::memmem::find(&lower, needle).is_some()
}

/// Search a **pre-lowercased** haystack — no allocation, just the memmem search.
/// Use when searching the same response body against many needles.
/// Needle must already be lowercase.
#[inline]
fn memmem_find_lower(pre_lowered: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(pre_lowered, needle).is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use crate::core::scanner::{ScanConfig, ScanContext};
    use std::path::PathBuf;

    fn make_ctx(server_uri: &str) -> ScanContext {
        ScanContext::new(ScanConfig {
            target: server_uri.to_string(),
            output: PathBuf::from("out.json"),
            threads: 5,
            rps: 100,
            silent: false,
            verbose: 0,
            scripts_dir: PathBuf::from("scripts"),
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false,
            port_scan_enabled: false,
            scope: "127.0.0.1".to_string(),
            timeout_secs: 5,
            user_agent: None,
            auth: crate::core::scanner::AuthMethod::default(),
            max_crawl_depth: 3,
            max_crawl_urls: 100,
            thorough: false,
        })
    }

    #[tokio::test]
    async fn test_missing_security_headers_no_extra_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let base   = client.get(&server.uri()).await.unwrap();
        let findings = check_security_headers(&base, &server.uri());
        // 6 required headers missing
        assert!(findings.len() >= 6);
    }

    #[tokio::test]
    async fn test_cors_wildcard() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("access-control-allow-origin", "*")
                    .set_body_string("OK"),
            )
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let base   = client.get(&server.uri()).await.unwrap();
        let findings = check_cors(&base, &server.uri());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("wildcard"));
    }

    #[tokio::test]
    async fn test_info_disclosure_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("server", "Apache/2.4.51")
                    .insert_header("x-powered-by", "PHP/8.2")
                    .insert_header("x-debug-token", "abc123")
                    .set_body_string("OK"),
            )
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let base   = client.get(&server.uri()).await.unwrap();
        let findings = check_info_disclosure(&base, &server.uri());
        // server version + x-powered-by + x-debug-token = 3
        assert_eq!(findings.len(), 3);
    }

    #[tokio::test]
    async fn test_403_bypass_parallel() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/admin"))
            .and(wiremock::matchers::header("X-Forwarded-For", "127.0.0.1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Admin"))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/admin"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let target = format!("{}/admin", server.uri());

        let result = try_403_bypass(&client, &target).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status, 200);
    }

    #[test]
    fn test_memmem_icase() {
        assert!(memmem_find_icase(b"You have an error in your SQL syntax", b"you have an error in your sql syntax"));
        assert!(memmem_find_icase(b"SQLSTATE[HY000]", b"sqlstate"));
        assert!(!memmem_find_icase(b"everything is fine", b"sqlstate"));
    }

    #[tokio::test]
    async fn test_check_cookies_no_extra_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "session=abc123; Path=/"),
            )
            .expect(1)
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let base   = client.get(&server.uri()).await.unwrap();
        let findings = check_cookies(&base, &server.uri());
        assert!(findings.len() >= 2);
    }

    #[test]
    fn test_path_mutations() {
        let mutations = generate_path_mutations("http://example.com/admin");
        assert!(!mutations.is_empty());
        assert!(mutations.iter().any(|m| m.ends_with('/')));
    }

    #[test]
    fn test_inject_param() {
        let query = vec![("id".to_string(), "1".to_string())];
        let url = inject_param("http://example.com/?id=1", "id", "'", &query, false);
        assert!(url.is_some());
        assert!(url.unwrap().contains("id=%27"));
    }
}
