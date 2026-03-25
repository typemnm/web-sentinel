use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

/// CVE record from the embedded database
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CveRecord {
    pub id: String,
    pub product: String,
    pub version_range: String,
    pub description: String,
    pub cvss_score: f64,
}

/// Embedded SQLite CVE database
pub struct CveDb {
    conn: Connection,
}

impl CveDb {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cves (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                cvss_score  REAL NOT NULL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS products (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
                product     TEXT NOT NULL,
                version_range TEXT NOT NULL DEFAULT '*'
            );

            CREATE INDEX IF NOT EXISTS idx_products_name ON products(product);
            ",
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn insert_cve(
        &self,
        id: &str,
        description: &str,
        cvss: f64,
        product: &str,
        version_range: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO cves (id, description, cvss_score) VALUES (?1, ?2, ?3)",
            params![id, description, cvss],
        )?;
        self.conn.execute(
            "INSERT INTO products (cve_id, product, version_range) VALUES (?1, ?2, ?3)",
            params![id, product, version_range],
        )?;
        Ok(())
    }

    /// Search CVEs by product name and version
    pub fn search(&self, product: &str, version: &str) -> Result<Vec<CveRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, p.product, p.version_range, c.description, c.cvss_score
             FROM cves c
             JOIN products p ON p.cve_id = c.id
             WHERE LOWER(p.product) LIKE LOWER(?1)",
        )?;

        let product_pattern = format!("%{}%", product);
        let rows = stmt.query_map(params![product_pattern], |row| {
            Ok(CveRecord {
                id: row.get(0)?,
                product: row.get(1)?,
                version_range: row.get(2)?,
                description: row.get(3)?,
                cvss_score: row.get(4)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            let rec = row?;
            if rec.version_range == "*" {
                results.push(rec);
            } else if let Some(max_ver) = rec.version_range.strip_prefix('<') {
                if version_lt(version, max_ver.trim()) {
                    results.push(rec);
                }
            } else if version.starts_with(&rec.version_range) {
                results.push(rec);
            }
        }
        Ok(results)
    }

    /// Pre-populate common CVEs for well-known web technologies
    pub fn seed_known_cves(&self) -> Result<()> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(()); // already seeded
        }

        let cves: &[(&str, &str, f64, &str, &str)] = &[
            // (cve_id, description, cvss, product, max_vulnerable_version)
            // Apache
            (
                "CVE-2021-44790",
                "Apache HTTP Server mod_lua buffer overflow (RCE possible)",
                9.8, "Apache", "<2.4.52",
            ),
            (
                "CVE-2021-41773",
                "Apache HTTP Server 2.4.49 path traversal and RCE",
                9.8, "Apache", "<2.4.50",
            ),
            // Nginx
            (
                "CVE-2021-23017",
                "Nginx resolver DNS response vulnerability leading to heap corruption",
                7.7, "Nginx", "<1.20.1",
            ),
            // Werkzeug / Flask
            (
                "CVE-2024-34069",
                "Werkzeug debugger RCE when debug mode is enabled on attacker-accessible network",
                7.5, "Werkzeug", "<3.0.3",
            ),
            (
                "CVE-2023-46136",
                "Werkzeug DoS via crafted multipart data with high resource consumption",
                7.5, "Werkzeug", "<3.0.1",
            ),
            (
                "CVE-2023-25577",
                "Werkzeug high resource consumption via crafted multipart form data",
                7.5, "Werkzeug", "<2.2.3",
            ),
            // WordPress
            (
                "CVE-2023-2745",
                "WordPress directory traversal via wp_lang parameter",
                5.4, "WordPress", "<6.2.1",
            ),
            (
                "CVE-2022-21661",
                "WordPress SQL injection via WP_Query",
                7.5, "WordPress", "<5.8.3",
            ),
            // jQuery
            (
                "CVE-2020-11022",
                "jQuery XSS via htmlPrefilter in versions before 3.5.0",
                6.1, "jQuery", "<3.5.0",
            ),
            (
                "CVE-2020-11023",
                "jQuery XSS via HTML containing <option> elements",
                6.1, "jQuery", "<3.5.0",
            ),
            (
                "CVE-2019-11358",
                "jQuery prototype pollution in extend function",
                6.1, "jQuery", "<3.4.0",
            ),
            // PHP
            (
                "CVE-2024-2756",
                "PHP cookie bypass via __Host-/__Secure- prefix validation flaw",
                6.5, "PHP", "<8.3.4",
            ),
            (
                "CVE-2023-3247",
                "PHP information disclosure via missing error check in SOAP",
                4.3, "PHP", "<8.2.8",
            ),
            // Express
            (
                "CVE-2024-29041",
                "Express.js open redirect via url.parse() bypass",
                6.1, "Express", "<4.19.2",
            ),
            // Django
            (
                "CVE-2024-24680",
                "Django potential DoS via intcomma template filter",
                7.5, "Django", "<5.0.2",
            ),
            // Spring Framework
            (
                "CVE-2022-22965",
                "Spring Framework RCE via data binding (Spring4Shell)",
                9.8, "Spring", "<5.3.18",
            ),
            // Laravel
            (
                "CVE-2021-3129",
                "Laravel Ignition RCE via insecure deserialization",
                9.8, "Laravel", "<8.4.2",
            ),
            // Drupal
            (
                "CVE-2018-7600",
                "Drupal RCE via Form API (Drupalgeddon 2)",
                9.8, "Drupal", "<8.5.1",
            ),
            // ASP.NET (IIS)
            (
                "CVE-2023-36899",
                "ASP.NET security feature bypass via elevation of privilege",
                8.8, "ASP.NET", "<8.0.0",
            ),
        ];

        self.conn.execute_batch("BEGIN")?;
        for (id, desc, cvss, product, version_range) in cves {
            self.insert_cve(id, desc, *cvss, product, version_range)?;
        }
        self.conn.execute_batch("COMMIT")?;

        Ok(())
    }
}

/// Strip non-numeric suffix from a version component (e.g. "52-debian" → "52")
fn strip_version_suffix(part: &str) -> Option<u32> {
    let trimmed = part.trim();
    // Take leading digits only (stops at first non-digit)
    let numeric: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    numeric.parse().ok()
}

/// Compare two version strings: returns true if `version` < `max_version`
fn version_lt(version: &str, max_version: &str) -> bool {
    let v: Vec<u32> = version
        .split('.')
        .filter_map(strip_version_suffix)
        .collect();
    let m: Vec<u32> = max_version
        .split('.')
        .filter_map(strip_version_suffix)
        .collect();

    for i in 0..v.len().max(m.len()) {
        let a = v.get(i).copied().unwrap_or(0);
        let b = m.get(i).copied().unwrap_or(0);
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    false // equal → not less than
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cve_db_insert_and_search() {
        let dir = tempdir().unwrap();
        let db = CveDb::open(dir.path().join("cves.db")).unwrap();

        db.insert_cve(
            "CVE-2021-44228",
            "Log4Shell - Remote code execution in log4j",
            10.0,
            "log4j",
            "<2.16.0",
        )
        .unwrap();

        let results = db.search("log4j", "2.14.1").unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "CVE-2021-44228");

        // Version 2.17.0 should NOT match <2.16.0
        let no_match = db.search("log4j", "2.17.0").unwrap();
        assert!(no_match.is_empty());

        // No match for unrelated product
        let no_results = db.search("nginx", "1.0.0").unwrap();
        assert!(no_results.is_empty());
    }

    #[test]
    fn test_seed_known_cves() {
        let dir = tempdir().unwrap();
        let db = CveDb::open(dir.path().join("cves.db")).unwrap();
        db.seed_known_cves().unwrap();

        // Werkzeug 2.0.0 < 3.0.3 → should match CVE-2024-34069
        let results = db.search("Werkzeug", "2.0.0").unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.id == "CVE-2024-34069"));

        // Werkzeug 3.1.6 >= 3.0.3 → should NOT match CVE-2024-34069
        let results = db.search("Werkzeug", "3.1.6").unwrap();
        assert!(!results.iter().any(|r| r.id == "CVE-2024-34069"));

        // jQuery 3.3.0 < 3.5.0 → should match CVE-2020-11022
        let results = db.search("jQuery", "3.3.0").unwrap();
        assert!(results.iter().any(|r| r.id == "CVE-2020-11022"));

        // Idempotent: calling twice doesn't duplicate
        db.seed_known_cves().unwrap();
        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))
            .unwrap();
        assert!(count > 0 && count <= 20);
    }

    #[test]
    fn test_version_lt() {
        assert!(version_lt("2.0.0", "3.0.3"));
        assert!(version_lt("3.0.2", "3.0.3"));
        assert!(!version_lt("3.0.3", "3.0.3")); // equal
        assert!(!version_lt("3.1.6", "3.0.3"));
        assert!(!version_lt("4.0.0", "3.0.3"));
        assert!(version_lt("1.20.0", "1.20.1"));
        assert!(!version_lt("1.20.1", "1.20.1"));
        assert!(version_lt("5.3.17", "5.3.18"));
        assert!(!version_lt("5.3.18", "5.3.18"));
    }
}
