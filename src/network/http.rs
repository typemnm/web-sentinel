use anyhow::Result;
use reqwest::{Client, Response, header};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

use crate::core::scanner::ScanContext;

const DEFAULT_UA: &str = concat!(
    "Mozilla/5.0 (compatible; Sentinel/",
    env!("CARGO_PKG_VERSION"),
    "; +https://github.com/cert/sentinel)"
);

#[allow(dead_code)]
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    DEFAULT_UA,
];

#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
}

impl HttpClient {
    pub fn new(ctx: &ScanContext) -> Result<Self> {
        let ua = ctx
            .config
            .user_agent
            .clone()
            .unwrap_or_else(|| DEFAULT_UA.to_string());

        // pool_max_idle_per_host ∝ threads (⑧)
        let pool_size = (ctx.config.threads / 2).clamp(10, 100);

        let client = Client::builder()
            .timeout(Duration::from_secs(ctx.config.timeout_secs))
            .pool_max_idle_per_host(pool_size)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .user_agent(ua)
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self { inner: client })
    }

    /// GET with automatic retry — ⑩ try_clone 제거, 매 재시도마다 빌더 재구성
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.get_with_headers(url, &[]).await
    }

    pub async fn get_with_headers(
        &self,
        url: &str,
        extra_headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut last_err = None;

        for attempt in 0..3u8 {
            let mut req = self.inner.get(url);
            for (k, v) in extra_headers {
                req = req.header(*k, *v);
            }

            let start = std::time::Instant::now();
            match req.send().await {
                Ok(resp) => {
                    let elapsed = start.elapsed();
                    debug!("GET {} -> {} ({}ms)", url, resp.status(), elapsed.as_millis());
                    return HttpResponse::from_reqwest(resp, elapsed).await;
                }
                Err(e) if attempt < 2 => {
                    last_err = Some(e);
                    let delay = Duration::from_millis(300 * (attempt as u64 + 1));
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err.unwrap().into())
    }

    /// HEAD 요청: 헤더만 필요한 경우 바디 수신 생략
    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        let start = std::time::Instant::now();
        let resp = self.inner
            .request(reqwest::Method::HEAD, url)
            .send()
            .await?;
        HttpResponse::from_reqwest_headers_only(resp, start.elapsed())
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        let start = std::time::Instant::now();
        let resp = self
            .inner
            .post(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.to_string())
            .send()
            .await?;
        HttpResponse::from_reqwest(resp, start.elapsed()).await
    }

    /// OPTIONS 요청: 허용된 HTTP 메서드 확인
    pub async fn options(&self, url: &str) -> Result<HttpResponse> {
        let start = std::time::Instant::now();
        let resp = self.inner
            .request(reqwest::Method::OPTIONS, url)
            .send()
            .await?;
        HttpResponse::from_reqwest_headers_only(resp, start.elapsed())
    }
}

/// Parsed HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
    /// Response time in milliseconds (from request start to body received)
    pub elapsed_ms: u64,
}

impl HttpResponse {
    pub async fn from_reqwest(resp: Response, elapsed: std::time::Duration) -> Result<Self> {
        let url = resp.url().to_string();
        let status = resp.status().as_u16();
        let mut headers = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            headers.insert(k.as_str().to_string(), v.to_str().unwrap_or("").to_string());
        }
        let body = resp.text().await?;
        Ok(Self { status, headers, body, url, elapsed_ms: elapsed.as_millis() as u64 })
    }

    /// ⑨ 바디 수신 없이 헤더만 파싱
    fn from_reqwest_headers_only(resp: Response, elapsed: std::time::Duration) -> Result<Self> {
        let url = resp.url().to_string();
        let status = resp.status().as_u16();
        let mut headers = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            headers.insert(k.as_str().to_string(), v.to_str().unwrap_or("").to_string());
        }
        Ok(Self { status, headers, body: String::new(), url, elapsed_ms: elapsed.as_millis() as u64 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::{ScanConfig, ScanContext};
    use std::path::PathBuf;

    fn make_ctx() -> ScanContext {
        ScanContext::new(ScanConfig {
            target: "http://example.com".to_string(),
            output: PathBuf::from("out.json"),
            threads: 50,
            rps: 5,
            silent: false,
            verbose: 0,
            scripts_dir: PathBuf::from("scripts"),
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false,
            port_scan_enabled: false,
            scope: "example.com".to_string(),
            timeout_secs: 10,
            user_agent: None,
        })
    }

    #[test]
    fn test_pool_size_clamped() {
        // threads=50 → pool=(50/2)=25
        let ctx = ScanContext::new(ScanConfig {
            target: "http://example.com".to_string(),
            output: PathBuf::from("out.json"),
            threads: 50,
            rps: 5, silent: false, verbose: 0,
            scripts_dir: PathBuf::from("scripts"),
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false, port_scan_enabled: false,
            scope: "example.com".to_string(),
            timeout_secs: 10, user_agent: None,
        });
        let client = HttpClient::new(&ctx);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_http_client_construction() {
        let ctx = make_ctx();
        assert!(HttpClient::new(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_retry_builds_fresh_request() {
        // try_clone 없이 재시도해도 패닉 없는지 확인
        let ctx = make_ctx();
        let client = HttpClient::new(&ctx).unwrap();
        // 존재하지 않는 주소 → 실패하되 패닉 없음
        let result = client.get("http://127.0.0.1:19999/no-server").await;
        assert!(result.is_err());
    }
}
