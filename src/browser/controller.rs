use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptions};
use tracing::{debug, info};

use crate::browser::xss::XssDetector;
use crate::core::scanner::Finding;

/// Launch headless Chrome and perform DOM-based vulnerability analysis
pub async fn scan_with_browser(target: &str) -> Result<Vec<Finding>> {
    tokio::task::spawn_blocking({
        let target = target.to_string();
        move || run_browser_scan_blocking(&target)
    })
    .await?
}

fn run_browser_scan_blocking(target: &str) -> Result<Vec<Finding>> {
    let options = LaunchOptions::default_builder()
        .headless(true)
        .sandbox(false) // required in some Linux envs
        .args(vec![
            std::ffi::OsStr::new("--no-sandbox"),
            std::ffi::OsStr::new("--disable-dev-shm-usage"),
            std::ffi::OsStr::new("--disable-gpu"),
            std::ffi::OsStr::new("--window-size=1280,720"),
        ])
        .build()
        .map_err(|e| anyhow!("Failed to build Chrome options: {:?}", e))?;

    let browser = Browser::new(options)
        .map_err(|e| anyhow!("Failed to launch Chrome: {:?}", e))?;

    let tab = browser.new_tab()
        .map_err(|e| anyhow!("Failed to open tab: {:?}", e))?;

    info!("[Browser] Navigating to: {}", target);
    tab.navigate_to(target)
        .map_err(|e| anyhow!("Navigation failed: {:?}", e))?
        .wait_until_navigated()
        .map_err(|e| anyhow!("Page load timeout: {:?}", e))?;

    // Capture title to verify page loaded
    let title: String = tab
        .evaluate("document.title", false)
        .ok()
        .and_then(|v| v.value.as_ref().and_then(|v| v.as_str().map(|s| s.to_string())))
        .unwrap_or_default();
    debug!("[Browser] Page title: {}", title);

    // DOM XSS detection
    let detector = XssDetector::new();
    let xss_findings = detector.scan(&tab, target)?;

    Ok(xss_findings)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_browser_module_compiles() {
        assert!(true);
    }
}
