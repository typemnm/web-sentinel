use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::core::scanner::ScanContext;

/// Common ports to scan when no custom list is provided
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1080, 1433, 1521, 2181, 3000, 3306, 3389, 4848, 5432, 5900,
    6379, 7001, 8080, 8443, 8888, 9200, 9300, 27017,
];

pub struct PortScanner {
    ctx: ScanContext,
}

impl PortScanner {
    pub fn new(ctx: ScanContext) -> Self {
        Self { ctx }
    }

    /// Async TCP connect scan - returns list of open ports
    pub async fn scan(&self, host: &str) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let sem = self.ctx.semaphore.clone();

        let mut handles = Vec::new();
        for &port in COMMON_PORTS {
            let host = host.to_string();
            let sem = sem.clone();
            let timeout_secs = self.ctx.config.timeout_secs;

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                if is_port_open(&host, port, timeout_secs).await {
                    Some(port)
                } else {
                    None
                }
            }));
        }

        for handle in handles {
            if let Ok(Some(port)) = handle.await {
                debug!("Open port: {}", port);
                open_ports.push(port);
            }
        }

        open_ports.sort_unstable();
        Ok(open_ports)
    }
}

async fn is_port_open(host: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", host, port);
    let dur = Duration::from_secs(timeout_secs.min(3)); // cap at 3s for port scan

    match addr.parse::<SocketAddr>() {
        Ok(sa) => timeout(dur, TcpStream::connect(sa)).await.is_ok_and(|r| r.is_ok()),
        Err(_) => {
            // Try resolution via tokio
            match tokio::net::lookup_host(&addr).await {
                Ok(mut addrs) => {
                    if let Some(sa) = addrs.next() {
                        timeout(dur, TcpStream::connect(sa)).await.is_ok_and(|r| r.is_ok())
                    } else {
                        false
                    }
                }
                Err(_) => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::{ScanConfig, ScanContext};
    use std::path::PathBuf;

    fn make_ctx() -> ScanContext {
        ScanContext::new(ScanConfig {
            target: "http://localhost".to_string(),
            output: PathBuf::from("out.json"),
            threads: 50,
            rps: 100,
            silent: false,
            verbose: 0,
            scripts_dir: PathBuf::from("scripts"),
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false,
            port_scan_enabled: true,
            scope: "localhost".to_string(),
            timeout_secs: 2,
            user_agent: None,
        })
    }

    #[tokio::test]
    async fn test_port_scan_localhost() {
        let ctx = make_ctx();
        let scanner = PortScanner::new(ctx);
        // Just verify the function runs without panic
        // Open ports depend on system configuration
        let result = scanner.scan("127.0.0.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_port_open_detection() {
        // Start a listener to ensure a port is open
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _accept = tokio::spawn(async move { listener.accept().await });

        let open = is_port_open("127.0.0.1", port, 2).await;
        assert!(open, "Port {} should be detected as open", port);
    }
}
