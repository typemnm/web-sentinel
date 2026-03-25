//! Finding deduplication and aggregation engine.
//!
//! Merges duplicate findings by (category, title_stem, param) and groups
//! identical low-severity findings (e.g., "Missing CSP") across URLs into
//! a single finding with affected URL count.

use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::debug;

use crate::core::scanner::{Finding, Severity};

/// Deduplicate and aggregate findings.
///
/// Rules:
/// 1. Same (category, title_normalized) on same URL → keep highest severity only
/// 2. Same (category, title_normalized) across different URLs at Low/Info severity
///    → merge into single finding with "N affected URLs" note
/// 3. Same (category, title_normalized) across URLs at High/Critical severity
///    → keep each (different URLs may need different remediation)
/// 4. Evidence is truncated to MAX_EVIDENCE_LEN chars
pub fn deduplicate(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    let before = findings.len();

    // Phase 1: Truncate evidence
    for f in &mut findings {
        if let Some(ref mut ev) = f.evidence {
            if ev.len() > MAX_EVIDENCE_LEN {
                ev.truncate(MAX_EVIDENCE_LEN);
                ev.push_str("...[truncated]");
            }
        }
    }

    // Phase 2: Same URL dedup — keep highest severity per (url, category, title_stem)
    let mut url_dedup: HashMap<String, Finding> = HashMap::new();
    for f in findings {
        let key = dedup_key(&f);
        url_dedup
            .entry(key)
            .and_modify(|existing| {
                if f.severity > existing.severity {
                    *existing = f.clone();
                }
            })
            .or_insert(f);
    }

    let deduped: Vec<Finding> = url_dedup.into_values().collect();

    // Phase 3: Merge low/info findings across URLs
    let (mergeable, mut keep): (Vec<_>, Vec<_>) =
        deduped.into_iter().partition(|f| {
            matches!(f.severity, Severity::Low | Severity::Info)
        });

    let mut merge_groups: HashMap<String, Vec<Finding>> = HashMap::new();
    for f in mergeable {
        let key = merge_key(&f);
        merge_groups.entry(key).or_default().push(f);
    }

    for (_key, group) in merge_groups {
        if group.len() <= 1 {
            keep.extend(group);
        } else {
            // Merge: take first finding, annotate with URL count
            let count = group.len();
            let urls: Vec<String> = group.iter().map(|f| f.url.clone()).collect();
            let sample_urls: String = urls.iter().take(3).cloned().collect::<Vec<_>>().join(", ");

            let mut merged = group.into_iter().next().unwrap();
            merged.description = format!(
                "{} (affects {} URLs, e.g.: {})",
                merged.description, count, sample_urls
            );
            merged.url = format!("{} URLs affected", count);
            keep.push(merged);
        }
    }

    // Phase 4: Sort by severity (Critical first)
    keep.sort_by(|a, b| b.severity.cmp(&a.severity));

    let after = keep.len();
    if before != after {
        debug!("Dedup: {} findings → {} findings (removed {})", before, after, before - after);
    }

    keep
}

const MAX_EVIDENCE_LEN: usize = 1024;

/// Key for same-URL dedup: (url, category_str, title_stem)
fn dedup_key(f: &Finding) -> String {
    format!(
        "{}|{:?}|{}",
        f.url,
        f.category,
        normalize_title(&f.title)
    )
}

/// Key for cross-URL merge: (category_str, title_stem) — no URL
fn merge_key(f: &Finding) -> String {
    format!("{:?}|{}", f.category, normalize_title(&f.title))
}

static QUOTED_PARAM_RE: OnceLock<regex::Regex> = OnceLock::new();
static PORT_RE: OnceLock<regex::Regex> = OnceLock::new();

/// Normalize title: strip URL-specific parts, param names, port numbers
fn normalize_title(title: &str) -> String {
    let lower = title.to_lowercase();
    // Remove parameter names in quotes (e.g., "SQLi in parameter 'id'" → "sqli in parameter")
    let re = QUOTED_PARAM_RE.get_or_init(|| regex::Regex::new(r"'[^']*'").unwrap());
    let cleaned = re.replace_all(&lower, "").to_string();
    // Remove port numbers
    let re2 = PORT_RE.get_or_init(|| regex::Regex::new(r":\d+").unwrap());
    re2.replace_all(&cleaned, "").to_string().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scanner::{FindingCategory, Severity};

    fn make_finding(sev: Severity, cat: FindingCategory, title: &str, url: &str) -> Finding {
        Finding::new(sev, cat, title, "desc", url)
    }

    #[test]
    fn test_same_url_dedup_keeps_highest_severity() {
        let findings = vec![
            make_finding(Severity::Medium, FindingCategory::SqlInjection, "SQLi in parameter 'id'", "http://a.com/?id=1"),
            make_finding(Severity::High, FindingCategory::SqlInjection, "SQLi in parameter 'id'", "http://a.com/?id=1"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].severity, Severity::High);
    }

    #[test]
    fn test_cross_url_low_findings_merged() {
        let findings = vec![
            make_finding(Severity::Low, FindingCategory::MissingHeader, "Missing header: CSP", "http://a.com/page1"),
            make_finding(Severity::Low, FindingCategory::MissingHeader, "Missing header: CSP", "http://a.com/page2"),
            make_finding(Severity::Low, FindingCategory::MissingHeader, "Missing header: CSP", "http://a.com/page3"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("3 URLs"));
    }

    #[test]
    fn test_high_findings_not_merged() {
        let findings = vec![
            make_finding(Severity::High, FindingCategory::SqlInjection, "SQLi in parameter 'id'", "http://a.com/page1?id=1"),
            make_finding(Severity::High, FindingCategory::SqlInjection, "SQLi in parameter 'name'", "http://a.com/page2?name=x"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_evidence_truncation() {
        let mut f = make_finding(Severity::Info, FindingCategory::Custom, "Test", "http://a.com");
        f.evidence = Some("x".repeat(5000));
        let result = deduplicate(vec![f]);
        let ev = result[0].evidence.as_ref().unwrap();
        assert!(ev.len() < 1100);
        assert!(ev.ends_with("...[truncated]"));
    }

    #[test]
    fn test_sorted_by_severity() {
        let findings = vec![
            make_finding(Severity::Info, FindingCategory::TechStack, "Tech A", "http://a.com"),
            make_finding(Severity::Critical, FindingCategory::CommandInjection, "CMDi", "http://a.com"),
            make_finding(Severity::Low, FindingCategory::MissingHeader, "Header", "http://a.com"),
        ];
        let result = deduplicate(findings);
        assert_eq!(result[0].severity, Severity::Critical);
    }

    #[test]
    fn test_empty_input() {
        assert!(deduplicate(vec![]).is_empty());
    }
}
