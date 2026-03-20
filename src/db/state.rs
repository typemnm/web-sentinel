use anyhow::Result;
use sled::Db;
use std::path::Path;

/// Persistent key-value state store (scan progress, visited URLs, etc.)
pub struct StateDb {
    db: Db,
}

#[allow(dead_code)]
impl StateDb {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.db.insert(key.as_bytes(), value.as_bytes())?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<String>> {
        match self.db.get(key.as_bytes())? {
            Some(v) => Ok(Some(String::from_utf8_lossy(&v).to_string())),
            None => Ok(None),
        }
    }

    pub fn remove(&self, key: &str) -> Result<()> {
        self.db.remove(key.as_bytes())?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    pub fn mark_visited(&self, url: &str) -> Result<()> {
        self.set(&format!("visited:{}", url), "1")
    }

    pub fn is_visited(&self, url: &str) -> Result<bool> {
        Ok(self.get(&format!("visited:{}", url))?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_db_roundtrip() {
        let dir = tempdir().unwrap();
        let db = StateDb::open(dir.path().join("state")).unwrap();

        db.set("foo", "bar").unwrap();
        assert_eq!(db.get("foo").unwrap(), Some("bar".to_string()));

        db.mark_visited("http://example.com").unwrap();
        assert!(db.is_visited("http://example.com").unwrap());
        assert!(!db.is_visited("http://other.com").unwrap());
    }
}
