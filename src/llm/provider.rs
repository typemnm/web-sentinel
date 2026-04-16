use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

use super::config::LlmConfig;
use super::types::{LlmAnalysisResponse, PromptMessage};

/// Trait for LLM provider implementations.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a chat completion request and return the parsed response plus token counts.
    async fn chat_completion(
        &self,
        messages: &[PromptMessage],
    ) -> Result<(LlmAnalysisResponse, u64, u64)>;
}

/// OpenAI-compatible chat completion provider.
/// Works with: OpenAI, Ollama (/v1), vLLM, LM Studio, llama.cpp server.
pub struct OpenAiCompatProvider {
    client: Client,
    api_base: String,
    model: String,
    api_key: String,
    max_tokens: u32,
    temperature: f32,
}

impl OpenAiCompatProvider {
    pub fn new(config: &LlmConfig) -> Result<Self> {
        let api_key = if config.api_key.is_empty() {
            std::env::var("SENTINEL_LLM_API_KEY").unwrap_or_default()
        } else {
            config.api_key.clone()
        };

        // Separate client from the scan HttpClient:
        // different timeout (120s vs 10s), different auth, no rate limiter needed.
        let client = Client::builder()
            .timeout(Duration::from_secs(config.api_timeout_secs))
            .pool_max_idle_per_host(2)
            .build()?;

        Ok(Self {
            client,
            api_base: config.api_base.trim_end_matches('/').to_string(),
            model: config.model.clone(),
            api_key,
            max_tokens: config.max_tokens,
            temperature: config.temperature,
        })
    }
}

// --- OpenAI chat/completions request/response structures ---

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: String,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<UsageInfo>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
struct UsageInfo {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn chat_completion(
        &self,
        messages: &[PromptMessage],
    ) -> Result<(LlmAnalysisResponse, u64, u64)> {
        let url = format!("{}/chat/completions", self.api_base);

        let chat_messages: Vec<ChatMessage> = messages
            .iter()
            .map(|m| ChatMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect();

        let request_body = ChatRequest {
            model: self.model.clone(),
            messages: chat_messages,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            // Request JSON output from compatible APIs (OpenAI, vLLM, etc.)
            response_format: Some(ResponseFormat {
                r#type: "json_object".to_string(),
            }),
        };

        let mut req = self.client.post(&url);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }

        let resp = req
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "LLM API returned HTTP {}: {}",
                status.as_u16(),
                &body[..body.len().min(500)]
            );
        }

        let chat_resp: ChatResponse = resp.json().await?;
        let content = chat_resp
            .choices
            .first()
            .ok_or_else(|| anyhow::anyhow!("LLM returned no choices"))?
            .message
            .content
            .clone();

        debug!(
            "LLM raw response ({} chars): {}",
            content.len(),
            &content[..content.len().min(300)]
        );

        let json_str = strip_markdown_fences(&content);
        let analysis: LlmAnalysisResponse = serde_json::from_str(json_str).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse LLM JSON: {} — raw: {}",
                e,
                &content[..content.len().min(400)]
            )
        })?;

        let (prompt_tokens, completion_tokens) = match chat_resp.usage {
            Some(u) => (u.prompt_tokens, u.completion_tokens),
            None => (0, 0),
        };

        Ok((analysis, prompt_tokens, completion_tokens))
    }
}

/// Strip ```json ... ``` fences that some models wrap around JSON output.
fn strip_markdown_fences(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.starts_with("```") {
        let start = trimmed.find('\n').map(|i| i + 1).unwrap_or(3);
        let end = trimmed.rfind("```").unwrap_or(trimmed.len());
        if end > start {
            return trimmed[start..end].trim();
        }
    }
    trimmed
}
