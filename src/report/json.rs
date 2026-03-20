use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use crate::core::scanner::{Finding, Severity};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub sentinel_version: String,
    pub target: String,
    pub scan_timestamp: chrono::DateTime<chrono::Utc>,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self { total: findings.len(), critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }
}

pub struct ReportWriter {
    output: PathBuf,
}

impl ReportWriter {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn write(&self, target: &str, findings: &[Finding]) -> Result<()> {
        let report = ScanReport {
            sentinel_version: env!("CARGO_PKG_VERSION").to_string(),
            target: target.to_string(),
            scan_timestamp: chrono::Utc::now(),
            summary: ReportSummary::from_findings(findings),
            findings: findings.to_vec(),
        };

        let json = serde_json::to_string_pretty(&report)?;

        let mut file = tokio::fs::File::create(&self.output).await?;
        file.write_all(json.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::{FindingCategory, Severity};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_report_write_and_parse() {
        let dir = tempdir().unwrap();
        let out = dir.path().join("report.json");

        let findings = vec![
            Finding::new(
                Severity::High,
                FindingCategory::SqlInjection,
                "SQL Injection in login",
                "Error-based SQLi detected",
                "http://example.com/login?id=1",
            ),
            Finding::new(
                Severity::Info,
                FindingCategory::TechStack,
                "Detected: nginx/1.24",
                "Nginx web server detected",
                "http://example.com",
            ),
        ];

        let writer = ReportWriter::new(out.clone());
        writer.write("http://example.com", &findings).await.unwrap();

        // Parse back and verify
        let content = tokio::fs::read_to_string(&out).await.unwrap();
        let parsed: ScanReport = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.summary.total, 2);
        assert_eq!(parsed.summary.high, 1);
        assert_eq!(parsed.summary.info, 1);
        assert_eq!(parsed.target, "http://example.com");

        // Verify JSON is valid
        let _ = serde_json::from_str::<serde_json::Value>(&content).unwrap();
    }
}
