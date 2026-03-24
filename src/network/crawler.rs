use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;
use tracing::{debug, info};

use crate::network::http::HttpClient;
use crate::network::scope::ScopeGuard;

/// Default max crawl depth for recursive crawling
#[allow(dead_code)]
pub const DEFAULT_MAX_DEPTH: usize = 3;

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
static JS_URL_RE: OnceLock<Regex> = OnceLock::new();
static SCRIPT_SRC_RE: OnceLock<Regex> = OnceLock::new();
static JS_STRING_API_RE: OnceLock<Regex> = OnceLock::new();

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
        // Extract URLs from JavaScript strings (fetch/axios/XMLHttpRequest patterns)
        JS_URL_RE.get_or_init(|| {
            Regex::new(r#"(?:fetch|axios\.\w+|\.open)\s*\(\s*["'`](/[a-zA-Z0-9/_\-\.?&=]+)["'`]"#).unwrap()
        });
        // Extract <script src="..."> tags for JS file fetching
        SCRIPT_SRC_RE.get_or_init(|| {
            Regex::new(r#"(?i)<script[^>]*\bsrc\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']"#).unwrap()
        });
        // Broader API path extraction from JS strings: "/api/...", "/rest/...", "/v1/..."
        JS_STRING_API_RE.get_or_init(|| {
            Regex::new(r#"["'`](/(?:api|rest|v[0-9]+|graphql|auth|admin|socket\.io|ftp|b2b|dataerasure|redirect|profile|security|snippet|metrics|promotion|quantityCheck|address|card|delivery|wallet|order|recycle|complaint|chatbot|track|basket|user|product|challenge|language|captcha|feedback|erasure|payment)[a-zA-Z0-9/_\-\.]*)["'`]"#).unwrap()
        });
        Self { client, scope }
    }

    /// Crawl a single page: extract links and forms from HTML
    #[allow(dead_code)]
    pub async fn crawl(&self, target: &str) -> Result<CrawlResult> {
        self.crawl_page(target).await
    }

    /// Recursive crawl: follow links up to max_depth, collecting all URLs and forms
    pub async fn crawl_recursive(&self, target: &str, max_depth: usize, max_urls: usize) -> Result<CrawlResult> {
        let mut all_result = CrawlResult::default();
        let mut visited = HashSet::new();
        visited.insert(normalize_url(target));

        let mut queue: Vec<(String, usize)> = vec![(target.to_string(), 0)];
        let mut total_visited = 0usize;

        while let Some((url, depth)) = queue.pop() {
            if depth > max_depth || total_visited >= max_urls {
                break;
            }

            match self.crawl_page(&url).await {
                Ok(page_result) => {
                    total_visited += 1;
                    // Enqueue newly discovered URLs for deeper crawling
                    for discovered_url in &page_result.urls {
                        let norm = normalize_url(discovered_url);
                        if visited.insert(norm) {
                            all_result.urls.push(discovered_url.clone());
                            if depth + 1 <= max_depth {
                                queue.push((discovered_url.clone(), depth + 1));
                            }
                        }
                    }
                    all_result.forms.extend(page_result.forms);
                }
                Err(e) => {
                    debug!("Crawl failed for {}: {:#}", url, e);
                }
            }
        }

        info!(
            "Recursive crawl complete: {} URLs visited, {} unique URLs, {} forms found (max_depth={})",
            total_visited,
            all_result.urls.len(),
            all_result.forms.len(),
            max_depth
        );
        Ok(all_result)
    }

    /// Internal: crawl a single page and extract links + forms + JS endpoints
    async fn crawl_page(&self, target: &str) -> Result<CrawlResult> {
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

        // Extract API endpoints from JavaScript (fetch/axios/XHR patterns)
        let js_re = JS_URL_RE.get().unwrap();
        for cap in js_re.captures_iter(&resp.body) {
            if let Some(path_match) = cap.get(1) {
                if let Ok(resolved) = base_url.join(path_match.as_str()) {
                    let url_str = resolved.as_str().to_string();
                    if self.scope.is_in_scope(&url_str)
                        && seen.insert(normalize_url(&url_str))
                    {
                        result.urls.push(url_str);
                    }
                }
            }
        }

        // Extract API endpoints from referenced JS files (SPA support)
        let script_src_re = SCRIPT_SRC_RE.get().unwrap();
        let js_api_re = JS_STRING_API_RE.get().unwrap();
        let mut js_urls: Vec<String> = Vec::new();
        for cap in script_src_re.captures_iter(&resp.body) {
            if let Some(src) = cap.get(1) {
                if let Ok(resolved) = base_url.join(src.as_str().trim()) {
                    js_urls.push(resolved.to_string());
                }
            }
        }
        // Fetch up to 10 JS files and extract API paths
        for js_url in js_urls.iter().take(10) {
            if let Ok(js_resp) = self.client.get(js_url).await {
                // Use the broader API path regex on JS file contents
                for cap in js_api_re.captures_iter(&js_resp.body) {
                    if let Some(path_match) = cap.get(1) {
                        let path = path_match.as_str();
                        // Skip overly generic or short paths
                        if path.len() < 4 { continue; }
                        if let Ok(resolved) = base_url.join(path) {
                            let url_str = resolved.as_str().to_string();
                            if self.scope.is_in_scope(&url_str)
                                && seen.insert(normalize_url(&url_str))
                            {
                                debug!("JS endpoint discovered: {} (from {})", url_str, js_url);
                                result.urls.push(url_str);
                            }
                        }
                    }
                }
                // Also apply the fetch/axios regex on JS files
                for cap in js_re.captures_iter(&js_resp.body) {
                    if let Some(path_match) = cap.get(1) {
                        if let Ok(resolved) = base_url.join(path_match.as_str()) {
                            let url_str = resolved.as_str().to_string();
                            if self.scope.is_in_scope(&url_str)
                                && seen.insert(normalize_url(&url_str))
                            {
                                result.urls.push(url_str);
                            }
                        }
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
