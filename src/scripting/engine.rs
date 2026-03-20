use anyhow::{anyhow, Result};
use futures::future::join_all;
use mlua::{Lua, Table, Value};
use tracing::{info, warn};

use crate::core::scanner::{Finding, FindingCategory, ScanContext, Severity};
use crate::network::http::HttpClient;

macro_rules! lua_err {
    ($e:expr) => {
        $e.map_err(|e| anyhow!("Lua error: {}", e))
    };
}

/// Lua 스크립팅 엔진 — ⑥ 스크립트별 spawn_blocking 병렬 실행
pub struct ScriptEngine {
    ctx: ScanContext,
    client: HttpClient,
}

impl ScriptEngine {
    pub async fn new(ctx: ScanContext, client: HttpClient) -> Result<Self> {
        Ok(Self { ctx, client })
    }

    /// ⑥ 모든 Lua 스크립트를 spawn_blocking 스레드에서 병렬 실행
    pub async fn run_all(&mut self, target: &str) -> Result<Vec<Finding>> {
        let scripts_dir = self.ctx.config.scripts_dir.clone();
        let lua_files: Vec<_> = std::fs::read_dir(&scripts_dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lua"))
            .collect();

        if lua_files.is_empty() {
            return Ok(vec![]);
        }

        // 스크립트별 독립 blocking 스레드 — Lua는 !Send이므로 spawn_blocking 필수
        let tasks: Vec<_> = lua_files
            .into_iter()
            .map(|path| {
                let client     = self.client.clone();
                let target_str = target.to_string();

                info!("Scheduling script: {}", path.display());

                tokio::task::spawn_blocking(move || -> Vec<Finding> {
                    match run_script_blocking(&path, &target_str, &client) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!("Script {} failed: {:#}", path.display(), e);
                            vec![]
                        }
                    }
                })
            })
            .collect();

        // 모든 스크립트 완료 대기
        let results = join_all(tasks).await;
        let findings = results
            .into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect();

        Ok(findings)
    }
}

/// spawn_blocking 스레드 내부에서 실행되는 순수 동기 함수
fn run_script_blocking(
    path: &std::path::Path,
    target: &str,
    client: &HttpClient,
) -> Result<Vec<Finding>> {
    let source = std::fs::read_to_string(path)?;
    let lua    = Lua::new();

    // Findings 수집용 로컬 Vec — Arc<Mutex> 없이 단순 Vec 사용
    let findings_local: std::sync::Arc<std::sync::Mutex<Vec<Finding>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    setup_sandbox(&lua, target, client, &findings_local)?;

    let result: Value = lua
        .load(&source)
        .eval()
        .map_err(|e| anyhow!("Lua eval error: {}", e))?;

    // 리턴값이 테이블이면 Finding으로 변환 (Lua VM 살아있는 동안 처리)
    if let Value::Table(tbl) = result {
        if let Some(f) = table_to_finding(&tbl, target) {
            findings_local.lock().unwrap().push(f);
        }
    }

    // Lua VM(과 클로저가 쥔 Arc clone)을 명시적으로 해제
    // drop 이후에야 Arc::try_unwrap이 성공함
    drop(lua);

    Ok(std::sync::Arc::try_unwrap(findings_local)
        .expect("Lua dropped: no other Arc refs remain")
        .into_inner()
        .unwrap())
}

/// Convert HttpResponse → Lua table (shared by all http.* functions)
fn resp_to_lua_table(lua_ctx: &Lua, r: &crate::network::http::HttpResponse) -> mlua::Result<mlua::Value> {
    let tbl = lua_ctx.create_table()?;
    tbl.set("status", r.status)?;
    tbl.set("body", r.body.clone())?;
    tbl.set("url", r.url.clone())?;
    tbl.set("elapsed_ms", r.elapsed_ms)?;
    let hdrs = lua_ctx.create_table()?;
    for (k, v) in &r.headers {
        hdrs.set(k.clone(), v.clone())?;
    }
    tbl.set("headers", hdrs)?;
    Ok(mlua::Value::Table(tbl))
}

fn setup_sandbox(
    lua: &Lua,
    target: &str,
    client: &HttpClient,
    findings: &std::sync::Arc<std::sync::Mutex<Vec<Finding>>>,
) -> Result<()> {
    let globals = lua.globals();

    for dangerous in &["io", "os", "dofile", "loadfile", "require", "package"] {
        lua_err!(globals.set(*dangerous, mlua::Value::Nil))?;
    }

    lua_err!(globals.set("TARGET", target))?;

    let http_table = lua_err!(lua.create_table())?;

    // --- http.get(url) ---
    let client_get = client.clone();
    let get_fn = lua_err!(lua.create_function(move |lua_ctx, url: String| {
        let client = client_get.clone();
        let resp = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.get(&url))
        });
        match resp {
            Ok(r) => resp_to_lua_table(&lua_ctx, &r),
            Err(e) => Err(mlua::Error::external(format!("http.get: {}", e))),
        }
    }))?;
    lua_err!(http_table.set("get", get_fn))?;

    // --- http.post(url, body) ---
    let client_post = client.clone();
    let post_fn = lua_err!(lua.create_function(move |lua_ctx, (url, body): (String, String)| {
        let client = client_post.clone();
        let resp = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.post(&url, &body))
        });
        match resp {
            Ok(r) => resp_to_lua_table(&lua_ctx, &r),
            Err(e) => Err(mlua::Error::external(format!("http.post: {}", e))),
        }
    }))?;
    lua_err!(http_table.set("post", post_fn))?;

    // --- http.head(url) ---
    let client_head = client.clone();
    let head_fn = lua_err!(lua.create_function(move |lua_ctx, url: String| {
        let client = client_head.clone();
        let resp = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(client.head(&url))
        });
        match resp {
            Ok(r) => resp_to_lua_table(&lua_ctx, &r),
            Err(e) => Err(mlua::Error::external(format!("http.head: {}", e))),
        }
    }))?;
    lua_err!(http_table.set("head", head_fn))?;

    // --- http.get_with_headers(url, headers_table) ---
    let client_gwh = client.clone();
    let gwh_fn = lua_err!(lua.create_function(move |lua_ctx, (url, hdrs_tbl): (String, Table)| {
        let client = client_gwh.clone();
        // Convert Lua table to Vec of (String, String)
        let mut extra: Vec<(String, String)> = Vec::new();
        for pair in hdrs_tbl.pairs::<String, String>() {
            if let Ok((k, v)) = pair {
                extra.push((k, v));
            }
        }
        let resp = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Convert to &str pairs for the API
                let refs: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                client.get_with_headers(&url, &refs).await
            })
        });
        match resp {
            Ok(r) => resp_to_lua_table(&lua_ctx, &r),
            Err(e) => Err(mlua::Error::external(format!("http.get_with_headers: {}", e))),
        }
    }))?;
    lua_err!(http_table.set("get_with_headers", gwh_fn))?;

    lua_err!(globals.set("http", http_table))?;

    // --- report.finding ---
    let findings_ref = findings.clone();
    let target_str   = target.to_string();
    let report_table = lua_err!(lua.create_table())?;

    let finding_fn = lua_err!(lua.create_function(
        move |_, args: (String, String, String, String, Option<String>)| {
            let (severity_s, category_s, title, description, url) = args;

            let severity = match severity_s.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high"     => Severity::High,
                "medium"   => Severity::Medium,
                "low"      => Severity::Low,
                _          => Severity::Info,
            };
            let category = match category_s.to_lowercase().as_str() {
                "xss"                         => FindingCategory::Xss,
                "sqli" | "sql_injection"      => FindingCategory::SqlInjection,
                "ssrf"                        => FindingCategory::Ssrf,
                "traversal" | "dir_traversal" => FindingCategory::DirectoryTraversal,
                "cmdi" | "command_injection"  => FindingCategory::CommandInjection,
                "crlf"                        => FindingCategory::CrlfInjection,
                "cors"                        => FindingCategory::Cors,
                _                             => FindingCategory::Custom,
            };

            let f = Finding::new(
                severity,
                category,
                title,
                description,
                url.unwrap_or_else(|| target_str.clone()),
            );

            findings_ref.lock().unwrap().push(f);
            Ok(())
        },
    ))?;

    lua_err!(report_table.set("finding", finding_fn))?;
    lua_err!(globals.set("report", report_table))?;

    Ok(())
}

fn table_to_finding(tbl: &Table, target: &str) -> Option<Finding> {
    let title:       Option<String> = tbl.get("title").ok();
    let description: Option<String> = tbl.get("description").ok();
    let severity_s:  String         = tbl.get("severity").unwrap_or_else(|_| "info".to_string());
    let url:         Option<String> = tbl.get("url").ok();

    let (title, description) = (title?, description?);

    let severity = match severity_s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high"     => Severity::High,
        "medium"   => Severity::Medium,
        "low"      => Severity::Low,
        _          => Severity::Info,
    };

    Some(Finding::new(
        severity,
        FindingCategory::Custom,
        title,
        description,
        url.unwrap_or_else(|| target.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::{ScanConfig, ScanContext};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_ctx(scripts_dir: PathBuf) -> ScanContext {
        ScanContext::new(ScanConfig {
            target: "http://example.com".to_string(),
            output: PathBuf::from("out.json"),
            threads: 5,
            rps: 5,
            silent: false,
            verbose: 0,
            scripts_dir,
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false,
            port_scan_enabled: false,
            scope: "example.com".to_string(),
            timeout_secs: 5,
            user_agent: None,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lua_basic_arithmetic() {
        let lua = Lua::new();
        let result: i64 = lua.load("return 1 + 1").eval().unwrap();
        assert_eq!(result, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lua_sandbox_io_blocked() {
        let dir    = tempdir().unwrap();
        let ctx    = make_ctx(dir.path().to_path_buf());
        let client = HttpClient::new(&ctx).unwrap();
        let findings = std::sync::Arc::new(std::sync::Mutex::new(vec![]));

        let lua = Lua::new();
        setup_sandbox(&lua, "http://example.com", &client, &findings).unwrap();

        let io_val: mlua::Value = lua.globals().get("io").unwrap();
        assert!(matches!(io_val, mlua::Value::Nil));

        let os_val: mlua::Value = lua.globals().get("os").unwrap();
        assert!(matches!(os_val, mlua::Value::Nil));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lua_script_report_finding() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("test_vuln.lua"),
            r#"report.finding("high", "custom", "Test Vuln", "Found via script", TARGET)"#,
        )
        .unwrap();

        let ctx    = make_ctx(dir.path().to_path_buf());
        let client = HttpClient::new(&ctx).unwrap();
        let mut engine = ScriptEngine::new(ctx, client).await.unwrap();

        let findings = engine.run_all("http://example.com").await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test Vuln");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multiple_scripts_parallel() {
        let dir = tempdir().unwrap();

        // 스크립트 3개 작성
        for i in 0..3 {
            std::fs::write(
                dir.path().join(format!("script_{}.lua", i)),
                format!(
                    r#"report.finding("info", "custom", "Script {}", "Parallel test", TARGET)"#,
                    i
                ),
            )
            .unwrap();
        }

        let ctx    = make_ctx(dir.path().to_path_buf());
        let client = HttpClient::new(&ctx).unwrap();
        let mut engine = ScriptEngine::new(ctx, client).await.unwrap();

        let findings = engine.run_all("http://example.com").await.unwrap();
        // 스크립트 3개 → finding 3개
        assert_eq!(findings.len(), 3);
    }
}
