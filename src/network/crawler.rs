use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;
use tracing::debug;

use crate::network::http::HttpClient;
use crate::network::scope::ScopeGuard;

/// A form discovered in HTML
#[derive(Debug, Clone)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String, // GET or POST
    pub fields: Vec<(String, String)>, // (name, default_value)
}

/// Crawl results from a single page
#[derive(Debug, Clone, Default)]
pub struct CrawlResult {
    pub urls: Vec<String>,
    pub forms: Vec<DiscoveredForm>,
}

static HREF_RE: OnceLock<Regex> = OnceLock::new();
static FORM_RE: OnceLock<Regex> = OnceLock::new();
static INPUT_RE: OnceLock<Regex> = OnceLock::new();
static ATTR_ACTION_RE: OnceLock<Regex> = OnceLock::new();
static ATTR_METHOD_RE: OnceLock<Regex> = OnceLock::new();
static ATTR_NAME_RE: OnceLock<Regex> = OnceLock::new();
static ATTR_VALUE_RE: OnceLock<Regex> = OnceLock::new();

pub struct Crawler {
    client: HttpClient,
    scope: ScopeGuard,
}

impl Crawler {
    pub fn new(client: HttpClient, scope: ScopeGuard) -> Self {
        HREF_RE.get_or_init(|| {
            Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"'#\s][^"'#]*)"#).unwrap()
        });
        FORM_RE.get_or_init(|| {
            Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap()
        });
        INPUT_RE.get_or_init(|| {
            Regex::new(r#"(?i)<(?:input|textarea|select)\b([^>]*)>"#).unwrap()
        });
        ATTR_ACTION_RE.get_or_init(|| {
            Regex::new(r#"(?i)action\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_METHOD_RE.get_or_init(|| {
            Regex::new(r#"(?i)method\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_NAME_RE.get_or_init(|| {
            Regex::new(r#"(?i)name\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_VALUE_RE.get_or_init(|| {
            Regex::new(r#"(?i)value\s*=\s*["']([^"']*)"#).unwrap()
        });
        Self { client, scope }
    }

    /// Crawl a page: extract links and forms from HTML
    pub async fn crawl(&self, target: &str) -> Result<CrawlResult> {
        let resp = self.client.get(target).await?;
        let base_url = url::Url::parse(target)?;
        let mut result = CrawlResult::default();
        let mut seen = HashSet::new();
        seen.insert(normalize_url(target));

        // Extract links (href, src attributes)
        let href_re = HREF_RE.get().unwrap();
        for cap in href_re.captures_iter(&resp.body) {
            if let Some(href) = cap.get(1) {
                let href_str = href.as_str().trim();
                if href_str.starts_with("javascript:")
                    || href_str.starts_with("mailto:")
                    || href_str.starts_with("data:")
                    || href_str.starts_with("tel:")
                {
                    continue;
                }
                if is_static_resource(href_str) {
                    continue;
                }
                if let Ok(resolved) = base_url.join(href_str) {
                    let url_str = resolved.as_str().to_string();
                    if self.scope.is_in_scope(&url_str)
                        && seen.insert(normalize_url(&url_str))
                    {
                        result.urls.push(url_str);
                    }
                }
            }
        }

        // Extract forms
        let form_re = FORM_RE.get().unwrap();
        let input_re = INPUT_RE.get().unwrap();
        let action_re = ATTR_ACTION_RE.get().unwrap();
        let method_re = ATTR_METHOD_RE.get().unwrap();
        let name_re = ATTR_NAME_RE.get().unwrap();
        let value_re = ATTR_VALUE_RE.get().unwrap();

        for form_cap in form_re.captures_iter(&resp.body) {
            let form_attrs = form_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let form_inner = form_cap.get(2).map(|m| m.as_str()).unwrap_or("");

            let action = action_re
                .captures(form_attrs)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .and_then(|a| base_url.join(a).ok())
                .map(|u| u.to_string())
                .unwrap_or_else(|| target.to_string());

            let method = method_re
                .captures(form_attrs)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_uppercase())
                .unwrap_or_else(|| "GET".to_string());

            let mut fields = Vec::new();
            for input_cap in input_re.captures_iter(form_inner) {
                let attrs = input_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if let Some(name) = name_re.captures(attrs).and_then(|c| c.get(1)) {
                    let value = value_re
                        .captures(attrs)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    fields.push((name.as_str().to_string(), value));
                }
            }

            if !fields.is_empty() && self.scope.is_in_scope(&action) {
                result.forms.push(DiscoveredForm {
                    action,
                    method,
                    fields,
                });
            }
        }

        debug!(
            "Crawled {}: {} links, {} forms",
            target,
            result.urls.len(),
            result.forms.len()
        );
        Ok(result)
    }
}

fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_lowercase()
}

fn is_static_resource(url: &str) -> bool {
    let lower = url.to_lowercase();
    let extensions = [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".tar",
    ];
    extensions.iter().any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("http://example.com/"),
            "http://example.com"
        );
        assert_eq!(
            normalize_url("http://example.com/path/"),
            "http://example.com/path"
        );
    }

    #[test]
    fn test_is_static_resource() {
        assert!(is_static_resource("/style.css"));
        assert!(is_static_resource("/app.js"));
        assert!(is_static_resource("/logo.PNG"));
        assert!(!is_static_resource("/api/data"));
        assert!(!is_static_resource("/login"));
    }

    #[test]
    fn test_form_regex() {
        FORM_RE.get_or_init(|| {
            Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap()
        });
        INPUT_RE.get_or_init(|| {
            Regex::new(r#"(?i)<(?:input|textarea|select)\b([^>]*)>"#).unwrap()
        });
        ATTR_ACTION_RE.get_or_init(|| {
            Regex::new(r#"(?i)action\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_METHOD_RE.get_or_init(|| {
            Regex::new(r#"(?i)method\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_NAME_RE.get_or_init(|| {
            Regex::new(r#"(?i)name\s*=\s*["']([^"']*)"#).unwrap()
        });
        ATTR_VALUE_RE.get_or_init(|| {
            Regex::new(r#"(?i)value\s*=\s*["']([^"']*)"#).unwrap()
        });

        let html = r#"<form action="/login" method="POST"><input type="text" name="username" value=""><input type="password" name="password"></form>"#;

        let form_re = FORM_RE.get().unwrap();
        let caps: Vec<_> = form_re.captures_iter(html).collect();
        assert_eq!(caps.len(), 1);

        let form_attrs = caps[0].get(1).unwrap().as_str();
        let action_re = ATTR_ACTION_RE.get().unwrap();
        let action = action_re
            .captures(form_attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str());
        assert_eq!(action, Some("/login"));

        let method_re = ATTR_METHOD_RE.get().unwrap();
        let method = method_re
            .captures(form_attrs)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str());
        assert_eq!(method, Some("POST"));

        let form_inner = caps[0].get(2).unwrap().as_str();
        let input_re = INPUT_RE.get().unwrap();
        let name_re = ATTR_NAME_RE.get().unwrap();
        let inputs: Vec<String> = input_re
            .captures_iter(form_inner)
            .filter_map(|c| {
                let attrs = c.get(1)?.as_str();
                name_re.captures(attrs)?.get(1).map(|m| m.as_str().to_string())
            })
            .collect();
        assert_eq!(inputs, vec!["username", "password"]);
    }
}
