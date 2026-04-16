use serde::Deserialize;

use crate::core::scanner::Severity;

/// Mirrors the [llm] section of sentinel.toml.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    /// Master switch. LLM phase is skipped entirely when false.
    pub enabled: bool,

    /// Provider identifier. Only "openai-compat" is supported.
    pub provider: String,

    /// Base URL for the OpenAI-compatible API.
    /// Examples:
    ///   "https://api.openai.com/v1"       (OpenAI)
    ///   "http://localhost:11434/v1"        (Ollama)
    ///   "http://localhost:8000/v1"         (vLLM)
    ///   "http://localhost:8080/v1"         (llama.cpp server)
    pub api_base: String,

    /// Model name sent in the chat completion request.
    pub model: String,

    /// API key. If empty, falls back to $SENTINEL_LLM_API_KEY env var.
    /// Local servers (Ollama, llama.cpp) typically need no key.
    pub api_key: String,

    /// Request timeout for LLM API calls in seconds.
    pub api_timeout_secs: u64,

    /// Maximum tokens the LLM may generate per completion.
    pub max_tokens: u32,

    /// Temperature for generation. 0.0 = deterministic.
    pub temperature: f32,

    /// Minimum severity of findings to send to LLM for analysis.
    pub min_severity: SeverityFilter,

    /// Maximum number of findings to analyze per scan.
    pub max_findings: usize,

    /// Maximum number of attack payloads the LLM may generate per finding.
    pub max_attacks_per_finding: usize,

    /// Dry-run: generate attack specs but do not execute them.
    pub dry_run: bool,

    /// Maximum character length for evidence included in prompts (prompt-injection mitigation).
    pub max_evidence_chars: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "openai-compat".to_string(),
            api_base: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o-mini".to_string(),
            api_key: String::new(),
            api_timeout_secs: 120,
            max_tokens: 2048,
            temperature: 0.2,
            min_severity: SeverityFilter::High,
            max_findings: 20,
            max_attacks_per_finding: 5,
            dry_run: false,
            max_evidence_chars: 4096,
        }
    }
}

/// Severity threshold for filtering findings sent to the LLM.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    /// Returns true if `finding_severity` meets or exceeds this threshold.
    pub fn accepts(&self, finding_severity: &Severity) -> bool {
        let to_ord = |s: &Severity| match s {
            Severity::Info => 0u8,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
        let threshold = match self {
            Self::Info => 0u8,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        };
        to_ord(finding_severity) >= threshold
    }
}
