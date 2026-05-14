use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};

mod browser;
mod core;
mod db;
mod llm;
mod network;
mod report;
mod scripting;

use crate::core::orchestrator::Orchestrator;
use crate::core::scanner::{AuthMethod, ScanConfig};

/// Project Sentinel - CERT Web Vulnerability Scanner
#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    version,
    about = "CERT-grade web vulnerability scanner with headless browser & Lua scripting",
    long_about = None
)]
pub struct Cli {
    /// Target domain or URL to scan
    #[arg(short, long, env = "SENTINEL_TARGET")]
    pub target: Option<String>,

    /// Output file for JSON report
    #[arg(short, long, default_value = "sentinel_report.json", env = "SENTINEL_OUTPUT")]
    pub output: PathBuf,

    /// Number of concurrent threads/tasks
    #[arg(long, default_value = "50", env = "SENTINEL_THREADS")]
    pub threads: usize,

    /// Maximum requests per second (rate limiting)
    #[arg(long, default_value = "10", env = "SENTINEL_RPS")]
    pub rps: u32,

    /// Silent mode (suppress non-critical output)
    #[arg(short, long)]
    pub silent: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Custom Lua script directory
    #[arg(long, default_value = "scripts", env = "SENTINEL_SCRIPTS")]
    pub scripts_dir: PathBuf,

    /// Skip Lua script phase entirely
    #[arg(long)]
    pub no_scripts: bool,

    /// Config file path
    #[arg(long, default_value = "sentinel.toml", env = "SENTINEL_CONFIG")]
    pub config: PathBuf,

    /// Enable headless browser scanning (slower, deeper)
    #[arg(long)]
    pub browser: bool,

    /// Disable port scanning
    #[arg(long)]
    pub no_ports: bool,

    /// Scope restriction: only scan this domain (auto-set from target)
    #[arg(long)]
    pub scope: Option<String>,

    /// Timeout per request in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// User-Agent string override
    #[arg(long)]
    pub user_agent: Option<String>,

    /// Authentication cookie (e.g. "session=abc123; token=xyz")
    #[arg(long, env = "SENTINEL_COOKIE")]
    pub cookie: Option<String>,

    /// Bearer token for Authorization header
    #[arg(long, env = "SENTINEL_TOKEN")]
    pub token: Option<String>,

    /// Basic auth credentials (format: "username:password")
    #[arg(long, env = "SENTINEL_BASIC_AUTH")]
    pub basic_auth: Option<String>,

    /// Custom auth header (format: "Header-Name:value")
    #[arg(long, env = "SENTINEL_AUTH_HEADER")]
    pub auth_header: Option<String>,

    /// Maximum crawl depth for recursive link discovery
    #[arg(long, default_value = "3")]
    pub crawl_depth: usize,

    /// Maximum number of URLs to visit during crawling
    #[arg(long, default_value = "100")]
    pub crawl_max_urls: usize,

    /// Thorough scan mode: more evasion variants, deeper checks (slower)
    #[arg(long)]
    pub thorough: bool,

    /// Enable LLM-assisted vulnerability analysis (Phase 7)
    #[arg(long)]
    pub llm: bool,

    /// LLM dry-run: generate attack payloads but don't execute them
    #[arg(long)]
    pub llm_dry_run: bool,

    /// LLM provider base URL, e.g. http://localhost:11434/v1 for Ollama
    #[arg(long, env = "SENTINEL_LLM_API_BASE")]
    pub llm_api_base: Option<String>,

    /// LLM model name, e.g. gpt-4o-mini or llama3
    #[arg(long, env = "SENTINEL_LLM_MODEL")]
    pub llm_model: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing/logging
    setup_logging(cli.verbose, cli.silent);

    info!("Project Sentinel v{} starting", env!("CARGO_PKG_VERSION"));

    let target = match &cli.target {
        Some(t) => t.clone(),
        None => {
            eprintln!("Error: --target is required. Use --help for usage.");
            std::process::exit(1);
        }
    };

    // Resolve scripts_dir: CWD-relative → binary-relative fallback
    let scripts_dir = if cli.scripts_dir.exists() {
        cli.scripts_dir.clone()
    } else if let Ok(exe) = std::env::current_exe() {
        let beside_bin = exe.parent().unwrap_or(exe.as_ref()).join(&cli.scripts_dir);
        if beside_bin.exists() {
            info!("Using scripts dir beside binary: {}", beside_bin.display());
            beside_bin
        } else {
            cli.scripts_dir.clone()
        }
    } else {
        cli.scripts_dir.clone()
    };

    // Resolve authentication method from CLI args (priority: cookie > token > basic > header)
    let auth = if let Some(cookie) = cli.cookie {
        AuthMethod::Cookie(cookie)
    } else if let Some(token) = cli.token {
        AuthMethod::Bearer(token)
    } else if let Some(basic) = cli.basic_auth {
        let parts: Vec<&str> = basic.splitn(2, ':').collect();
        if parts.len() == 2 {
            AuthMethod::Basic(parts[0].to_string(), parts[1].to_string())
        } else {
            eprintln!("Error: --basic-auth must be in format 'username:password'");
            std::process::exit(1);
        }
    } else if let Some(header) = cli.auth_header {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() == 2 {
            AuthMethod::CustomHeader(parts[0].to_string(), parts[1].trim().to_string())
        } else {
            eprintln!("Error: --auth-header must be in format 'Header-Name:value'");
            std::process::exit(1);
        }
    } else {
        AuthMethod::None
    };

    // Build LLM config: defaults, then apply CLI overrides
    let mut llm_config = llm::config::LlmConfig::default();
    if cli.llm {
        llm_config.enabled = true;
    }
    if cli.llm_dry_run {
        llm_config.dry_run = true;
    }
    if let Some(base) = cli.llm_api_base {
        llm_config.api_base = base;
    }
    if let Some(model) = cli.llm_model {
        llm_config.model = model;
    }

    let scan_config = ScanConfig {
        target: target.clone(),
        output: cli.output.clone(),
        threads: cli.threads,
        rps: cli.rps,
        silent: cli.silent,
        verbose: cli.verbose,
        scripts_dir,
        config_path: cli.config.clone(),
        browser_enabled: cli.browser,
        port_scan_enabled: !cli.no_ports,
        scope: cli.scope.unwrap_or(target),
        timeout_secs: cli.timeout,
        user_agent: cli.user_agent.clone(),
        auth,
        max_crawl_depth: cli.crawl_depth,
        max_crawl_urls: cli.crawl_max_urls,
        thorough: cli.thorough,
        llm_enabled: llm_config.enabled,
        llm_config,
        no_scripts: cli.no_scripts,
    };

    let mut orchestrator = Orchestrator::new(scan_config).await?;

    if let Err(e) = orchestrator.run().await {
        error!("Scan failed: {:#}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn setup_logging(verbose: u8, silent: bool) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let level = if silent {
        "warn"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sentinel={}", level)));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).compact())
        .init();
}
