use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};

mod browser;
mod core;
mod db;
mod network;
mod report;
mod scripting;

use crate::core::orchestrator::Orchestrator;
use crate::core::scanner::ScanConfig;

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
