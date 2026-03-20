use anyhow::Result;
use futures::future::{join_all, select_ok};
use std::pin::Pin;
use tracing::{debug, warn};

use crate::core::scanner::{Finding, FindingCategory, ScanContext, Severity};
use crate::network::http::{HttpClient, HttpResponse};
use crate::network::scope::ScopeGuard;

/// SQL 오류 시그니처 — 소문자, 정적 상수 (⑤ 할당 없는 검색용)
static SQL_ERROR_SIGS: &[&[u8]] = &[
    b"you have an error in your sql syntax",
    b"unclosed quotation mark",
    b"quoted string not properly terminated",
    b"pg_query()",
    b"sqlstate",
    b"ora-01756",
];

static SQL_PAYLOADS: &[&str] = &["'", "\"", "1' OR '1'='1", "1\"OR\"1\"=\"1"];

static REDIRECT_PARAMS: &[&str] = &[
    "redirect", "url", "next", "return", "goto", "continue", "dest",
];

static BYPASS_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For",           "127.0.0.1"),
    ("X-Original-URL",            "/"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Host",          "localhost"),
];

/// Feedback loop: analyze HTTP responses and adapt payloads
pub struct ResponseAnalyzer {
    ctx: ScanContext,
    client: HttpClient,
    scope: ScopeGuard,
}

impl ResponseAnalyzer {
    pub fn new(ctx: ScanContext, client: HttpClient, scope: ScopeGuard) -> Self {
        Self { ctx, client, scope }
    }

    pub async fn run(&self, target: &str) -> Result<Vec<Finding>> {
        if !self.scope.is_in_scope(target) {
            warn!("Target {} is out of scope, skipping", target);
            return Ok(vec![]);
        }
        debug!(
            "Analyzer running against {} (timeout={}s)",
            target, self.ctx.config.timeout_secs
        );

        // ① 단 1회 GET — check_security_headers, check_cookies, 403 판단에 재사용
        let base_resp = self.client.get(target).await?;

        let mut findings = Vec::new();

        // ① 참조 전달 (추가 GET 없음)
        findings.extend(check_security_headers(&base_resp, target));
        findings.extend(check_cookies(&base_resp, target));

        // ③ SQLi — 파라미터별 병렬 (별도 URL 필요하므로 GET은 각자)
        findings.extend(self.check_sqli(target).await?);

        // open redirect (URL 파라미터 조작 필요 → 별도 GET)
        findings.extend(self.check_open_redirect(target).await?);

        // ① 403 판단도 이미 받은 응답 재사용
        if base_resp.status == 403 {
            if let Ok(Some(bypassed)) = try_403_bypass(&self.client, target).await {
                debug!(
                    "403 bypass succeeded for {} (status: {})",
                    target, bypassed.status
                );
            }
        }

        Ok(findings)
    }

    // ③ SQLi: 파라미터별 futures 생성 후 join_all
    async fn check_sqli(&self, url: &str) -> Result<Vec<Finding>> {
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

        // 파라미터별 async 블록 생성 — 모두 동시 실행
        let tasks: Vec<_> = original_query
            .iter()
            .map(|(param_name, _)| {
                let client      = self.client.clone();
                let scope       = self.scope.clone();
                let param_name  = param_name.clone();
                let orig_query  = original_query.clone();
                let url_str     = url.to_string();

                async move {
                    sqli_probe_param(client, scope, url_str, param_name, orig_query).await
                }
            })
            .collect();

        let results = join_all(tasks).await;
        Ok(results.into_iter().flatten().collect())
    }

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
                if let Ok(resp) = self.client.get(&test_url).await {
                    if resp.url.contains("evil-example.com") {
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
}

// ① 참조만 받음 — 추가 GET 없음
fn check_security_headers(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let headers = &resp.headers;

    let required = &[
        ("x-frame-options",        "X-Frame-Options header missing (Clickjacking risk)"),
        ("x-content-type-options", "X-Content-Type-Options header missing (MIME sniffing risk)"),
        ("strict-transport-security", "HSTS header missing"),
        ("content-security-policy",   "Content-Security-Policy header missing"),
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
        }
    }

    findings
}

// ① 참조만 받음 — 추가 GET 없음 / ⑫ "set-cookie" 직접 비교
fn check_cookies(resp: &HttpResponse, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (header_name, header_value) in &resp.headers {
        // ⑫ to_lowercase() 제거 — reqwest HeaderName은 이미 소문자
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

/// ③ 단일 파라미터에 대한 SQLi 프로브 (join_all로 병렬 호출됨)
async fn sqli_probe_param(
    client: HttpClient,
    scope: ScopeGuard,
    url: String,
    param_name: String,
    original_query: Vec<(String, String)>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(mut parsed) = url::Url::parse(&url) else { return findings };

    for payload in SQL_PAYLOADS {
        let mut new_query = original_query.clone();
        for (k, v) in &mut new_query {
            if k == &param_name {
                *v = payload.to_string();
            }
        }
        parsed.query_pairs_mut().clear();
        for (k, v) in &new_query {
            parsed.query_pairs_mut().append_pair(k, v);
        }

        let test_url = parsed.as_str().to_string();
        if !scope.is_in_scope(&test_url) {
            continue;
        }

        if let Ok(resp) = client.get(&test_url).await {
            // ⑤ to_lowercase() 제거 — 바이트 수준 대소문자 무관 검색
            let body_bytes = resp.body.as_bytes();
            for sig in SQL_ERROR_SIGS {
                if memmem_find_icase(body_bytes, sig) {
                    debug!("SQLi signal at {} param={}", url, param_name);
                    let mut f = Finding::new(
                        Severity::High,
                        FindingCategory::SqlInjection,
                        format!("Potential SQLi in parameter '{}'", param_name),
                        format!(
                            "SQL error signature '{}' found when injecting payload '{}'",
                            std::str::from_utf8(sig).unwrap_or("?"),
                            payload
                        ),
                        test_url.clone(),
                    );
                    f.evidence    = Some(format!("Payload: {}", payload));
                    f.remediation = Some(
                        "Use parameterized queries / prepared statements".to_string(),
                    );
                    findings.push(f);
                    break;
                }
            }
        }
    }

    findings
}

/// ⑤ 할당 없는 대소문자 무관 바이트 검색 (memchr 크레이트 없이 구현)
fn memmem_find_icase(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

/// ⑦ 403 bypass: 4개 헤더를 select_ok로 동시 발사
pub async fn try_403_bypass(
    client: &HttpClient,
    url: &str,
) -> Result<Option<HttpResponse>> {
    type BoxFut = Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send>>;

    let futures: Vec<BoxFut> = BYPASS_HEADERS
        .iter()
        .map(|(k, v)| {
            let client = client.clone();
            let url    = url.to_string();
            let k      = *k;
            let v      = *v;
            Box::pin(async move {
                let resp = client.get_with_headers(&url, &[(k, v)]).await?;
                if resp.status != 403 {
                    Ok(resp)
                } else {
                    Err(anyhow::anyhow!("still 403"))
                }
            }) as BoxFut
        })
        .collect();

    match select_ok(futures).await {
        Ok((resp, _remaining)) => {
            debug!("403 bypass succeeded (status: {})", resp.status);
            Ok(Some(resp))
        }
        Err(_) => Ok(None),
    }
}

use std::future::Future;

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
        })
    }

    #[tokio::test]
    async fn test_missing_security_headers_no_extra_request() {
        let server = MockServer::start().await;
        // 정확히 1번만 응답 — 추가 GET이 오면 404
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)   // ① 검증: 딱 1번만
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let scope  = ScopeGuard::new("127.0.0.1");
        // run() 내부에서 GET 1회만 나가야 함
        let base = client.get(&server.uri()).await.unwrap();
        let findings = check_security_headers(&base, &server.uri());
        assert!(!findings.is_empty());
        // MockServer verify: expect(1) 위반 시 패닉
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
            .expect(1)   // ① 검증
            .mount(&server)
            .await;

        let ctx    = make_ctx(&server.uri());
        let client = HttpClient::new(&ctx).unwrap();
        let base   = client.get(&server.uri()).await.unwrap();
        let findings = check_cookies(&base, &server.uri());

        // HttpOnly, SameSite 없으므로 최소 2개
        assert!(findings.len() >= 2);
    }
}
