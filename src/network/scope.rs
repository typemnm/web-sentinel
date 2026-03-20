use url::Url;

/// Scope guard: rejects URLs that are outside the allowed domain
#[derive(Clone)]
pub struct ScopeGuard {
    allowed_host: String,
}

impl ScopeGuard {
    pub fn new(scope: &str) -> Self {
        // Normalize: strip scheme if present
        let host = if let Ok(parsed) = Url::parse(scope) {
            parsed.host_str().unwrap_or(scope).to_string()
        } else {
            scope.to_string()
        };
        Self { allowed_host: host }
    }

    /// Returns true if the URL is within scope
    pub fn is_in_scope(&self, url: &str) -> bool {
        match Url::parse(url) {
            Ok(parsed) => {
                let host = parsed.host_str().unwrap_or("");
                host == self.allowed_host || host.ends_with(&format!(".{}", self.allowed_host))
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_guard() {
        let guard = ScopeGuard::new("example.com");
        assert!(guard.is_in_scope("http://example.com/path"));
        assert!(guard.is_in_scope("https://sub.example.com/x"));
        assert!(!guard.is_in_scope("https://evil.com/"));
        assert!(!guard.is_in_scope("https://notexample.com/"));
    }
}
