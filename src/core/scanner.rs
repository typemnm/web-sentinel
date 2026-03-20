use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Core scan configuration passed throughout the application
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScanConfig {
    pub target: String,
    pub output: PathBuf,
    pub threads: usize,
    pub rps: u32,
    pub silent: bool,
    pub verbose: u8,
    pub scripts_dir: PathBuf,
    pub config_path: PathBuf,
    pub browser_enabled: bool,
    pub port_scan_enabled: bool,
    pub scope: String,
    pub timeout_secs: u64,
    pub user_agent: Option<String>,
}

/// Shared scan context (passed via Arc to all async tasks)
#[derive(Clone)]
pub struct ScanContext {
    pub config: Arc<ScanConfig>,
    pub semaphore: Arc<Semaphore>,
}

impl ScanContext {
    pub fn new(config: ScanConfig) -> Self {
        let threads = config.threads;
        Self {
            semaphore: Arc::new(Semaphore::new(threads)),
            config: Arc::new(config),
        }
    }
}

/// A single discovered finding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub url: String,
    pub evidence: Option<String>,
    pub cve: Option<String>,
    pub remediation: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Finding {
    pub fn new(
        severity: Severity,
        category: FindingCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            category,
            title: title.into(),
            description: description.into(),
            url: url.into(),
            evidence: None,
            cve: None,
            remediation: None,
            timestamp: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Xss,
    SqlInjection,
    OpenPort,
    TechStack,
    Cve,
    MissingHeader,
    InsecureCookie,
    DirectoryTraversal,
    Ssrf,
    CommandInjection,
    CrlfInjection,
    Cors,
    InformationDisclosure,
    Custom,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_context_semaphore() {
        let config = ScanConfig {
            target: "http://example.com".to_string(),
            output: PathBuf::from("out.json"),
            threads: 10,
            rps: 5,
            silent: false,
            verbose: 0,
            scripts_dir: PathBuf::from("scripts"),
            config_path: PathBuf::from("sentinel.toml"),
            browser_enabled: false,
            port_scan_enabled: true,
            scope: "example.com".to_string(),
            timeout_secs: 10,
            user_agent: None,
        };

        let ctx = ScanContext::new(config);
        assert_eq!(ctx.semaphore.available_permits(), 10);

        // Spawn 1000 dummy tasks and verify all complete
        let sem = ctx.semaphore.clone();
        let mut handles = Vec::new();
        for _ in 0..1000 {
            let s = sem.clone();
            handles.push(tokio::spawn(async move {
                let _permit = s.acquire().await.unwrap();
                tokio::task::yield_now().await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}
