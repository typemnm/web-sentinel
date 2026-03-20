use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

use crate::network::http::HttpClient;

#[derive(Debug, Clone)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    #[allow(dead_code)]
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub technologies: Vec<Technology>,
    #[allow(dead_code)]
    pub server: Option<String>,
    #[allow(dead_code)]
    pub powered_by: Option<String>,
}

struct FingerprintPattern {
    name: String,
    category: String,
    header_patterns: Vec<(String, Regex)>,
    body_patterns: Vec<(Regex, Option<usize>)>,
}

// ④ 프로세스 수명 동안 1회만 컴파일 — 이후 호출은 포인터 반환만 수행
static PATTERNS: OnceLock<Vec<FingerprintPattern>> = OnceLock::new();

/// Wappalyzer-style fingerprinting engine
pub struct Fingerprinter;

impl Fingerprinter {
    /// ④ new()는 OnceLock 초기화 이후 비용 제로
    pub fn new() -> Self {
        PATTERNS.get_or_init(build_patterns);
        Self
    }

    pub async fn detect(&self, url: &str, client: &HttpClient) -> Result<FingerprintResult> {
        let patterns = PATTERNS.get().expect("patterns initialized in new()");

        let resp    = client.get(url).await?;
        let body    = &resp.body;
        let headers = &resp.headers;

        let server     = headers.get("server").cloned();
        let powered_by = headers.get("x-powered-by").cloned();

        let mut technologies = Vec::new();

        for pat in patterns {
            let mut matched = false;
            let mut version = None;

            for (header_name, regex) in &pat.header_patterns {
                if let Some(val) = headers.get(header_name) {
                    if let Some(caps) = regex.captures(val) {
                        matched = true;
                        version = caps.get(1).map(|m| m.as_str().to_string());
                        break;
                    }
                }
            }

            if !matched {
                for (regex, ver_group) in &pat.body_patterns {
                    if let Some(caps) = regex.captures(body) {
                        matched = true;
                        if let Some(g) = ver_group {
                            version = caps.get(*g).map(|m| m.as_str().to_string());
                        }
                        break;
                    }
                }
            }

            if matched {
                debug!("Detected: {} {:?}", pat.name, version);
                technologies.push(Technology {
                    name:     pat.name.clone(),
                    version,
                    category: pat.category.clone(),
                });
            }
        }

        if let Some(ref s) = server {
            let server_name = s.to_lowercase();
            let prefix      = server_name.split('/').next().unwrap_or("");
            if !technologies.iter().any(|t| t.name.to_lowercase() == prefix) {
                let name = s.split('/').next().unwrap_or(s).to_string();
                let ver  = s.split('/').nth(1)
                    .map(|v| v.split_whitespace().next().unwrap_or("").to_string());
                technologies.push(Technology {
                    name,
                    version: ver,
                    category: "Web Server".to_string(),
                });
            }
        }

        Ok(FingerprintResult { technologies, server, powered_by })
    }
}

fn build_patterns() -> Vec<FingerprintPattern> {
    let mut patterns = Vec::new();

    macro_rules! add_pattern {
        ($name:expr, $cat:expr, headers: [$($hk:expr => $hv:expr),*], body: [$($bv:expr $(=> $bg:expr)?),*]) => {{
            #[allow(unused_mut)]
            let mut hp = Vec::new();
            $(
                if let Ok(r) = Regex::new($hv) {
                    hp.push(($hk.to_string(), r));
                }
            )*
            #[allow(unused_mut)]
            let mut bp = Vec::new();
            $(
                if let Ok(r) = Regex::new($bv) {
                    #[allow(unused_variables)]
                    let vg: Option<usize> = None;
                    $(let vg = Some($bg);)?
                    bp.push((r, vg));
                }
            )*
            patterns.push(FingerprintPattern {
                name: $name.to_string(),
                category: $cat.to_string(),
                header_patterns: hp,
                body_patterns: bp,
            });
        }};
    }

    // Web Servers
    add_pattern!("Apache", "Web Server",
        headers: ["server" => r"Apache(?:/([0-9.]+))?"], body: []);
    add_pattern!("Nginx", "Web Server",
        headers: ["server" => r"[Nn]ginx(?:/([0-9.]+))?"], body: []);
    add_pattern!("IIS", "Web Server",
        headers: ["server" => r"Microsoft-IIS(?:/([0-9.]+))?"], body: []);

    // CMS
    add_pattern!("WordPress", "CMS",
        headers: [],
        body: [r"wp-content/|wp-includes/", r#"<meta name="generator" content="WordPress ([0-9.]+)"# => 1]);
    add_pattern!("Drupal", "CMS",
        headers: ["x-generator" => r"Drupal ([0-9.]+)"],
        body: [r"/sites/default/files/", r#"Drupal.settings"#]);
    add_pattern!("Joomla", "CMS",
        headers: [],
        body: [r"/components/com_", r#"Joomla! - Open Source Content Management"#]);

    // Frameworks
    add_pattern!("Laravel", "Framework",
        headers: [], body: [r"laravel_session|XSRF-TOKEN"]);
    add_pattern!("Django", "Framework",
        headers: ["x-frame-options" => r"SAMEORIGIN"],
        body: [r"csrfmiddlewaretoken"]);
    add_pattern!("Spring", "Framework",
        headers: ["x-application-context" => r".*"],
        body: [r#"Whitelabel Error Page|Spring Framework"#]);
    add_pattern!("Express", "Framework",
        headers: ["x-powered-by" => r"Express"], body: []);

    // Languages
    add_pattern!("PHP", "Language",
        headers: ["x-powered-by" => r"PHP(?:/([0-9.]+))?"],
        body: [r#"\.php[?#]?"#]);
    add_pattern!("ASP.NET", "Language",
        headers: ["x-aspnet-version" => r"([0-9.]+)", "x-powered-by" => r"ASP\.NET"],
        body: [r"__VIEWSTATE|__EVENTVALIDATION"]);

    // Databases
    add_pattern!("MySQL", "Database",
        headers: [],
        body: [r"You have an error in your SQL syntax|mysql_fetch|MySQL server"]);
    add_pattern!("PostgreSQL", "Database",
        headers: [],
        body: [r"pg_query\(\)|PostgreSQL query failed|ERROR:\s+syntax error"]);

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_build_once() {
        let _fp1 = Fingerprinter::new();
        let _fp2 = Fingerprinter::new();
        // 두 번 호출해도 패턴은 1회만 빌드됨 — OnceLock 검증
        let p1 = PATTERNS.get().unwrap().as_ptr();
        let _ = Fingerprinter::new();
        let p2 = PATTERNS.get().unwrap().as_ptr();
        assert_eq!(p1, p2, "PATTERNS must be built only once");
    }

    #[test]
    fn test_patterns_not_empty() {
        Fingerprinter::new();
        let patterns = PATTERNS.get().unwrap();
        assert!(!patterns.is_empty());
        // 최소 14개 패턴 보장
        assert!(patterns.len() >= 14);
    }
}
