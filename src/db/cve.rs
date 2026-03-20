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
            // Simple version check: if version_range is '*' match all
            if rec.version_range == "*" || version.starts_with(&rec.version_range) {
                results.push(rec);
            }
        }
        Ok(results)
    }
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
            "2.",
        )
        .unwrap();

        let results = db.search("log4j", "2.14.1").unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "CVE-2021-44228");

        // No match for unrelated product
        let no_results = db.search("nginx", "1.0.0").unwrap();
        assert!(no_results.is_empty());
    }
}
