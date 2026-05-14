use anyhow::Result;
use obscura_browser::{BrowserContext, Page};
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

use crate::browser::xss::XssDetector;
use crate::core::scanner::Finding;

/// Perform DOM-based vulnerability analysis using the obscura browser engine.
pub async fn scan_with_browser(target: &str) -> Result<Vec<Finding>> {
    let ctx_id = Uuid::new_v4().to_string();
    let context = Arc::new(BrowserContext::new(ctx_id.clone()));
    let mut page = Page::new(ctx_id, context);

    info!("[Browser] Navigating to: {}", target);
    page.navigate(target)
        .await
        .map_err(|e| anyhow::anyhow!("Navigation failed: {:?}", e))?;

    debug!("[Browser] Page title: {}", page.title);

    let detector = XssDetector::new();
    let xss_findings = detector.scan(&mut page, target).await?;

    Ok(xss_findings)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_browser_module_compiles() {
        assert!(true);
    }
}
