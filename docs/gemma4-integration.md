# Gemma4 (gemma3:27b) LLM Integration

**Date:** 2026-05-03  
**Status:** ✅ Verified and Active

## Overview

Sentinel's LLM plugin (Phase 7) is now connected to **Gemma 3 27B** served locally via Ollama.
The model analyzes high/critical vulnerability findings and generates targeted attack payloads.

## Environment

| Component | Status | Details |
|-----------|--------|---------|
| Ollama daemon | ✅ Running | `http://localhost:11434` |
| Model loaded | ✅ Active | `gemma3:27b` (owned_by: library) |
| Sentinel binary | ✅ Compiled | `/home/typemnm/sentinel/target/debug/sentinel` (292 MB, 2026-05-03) |
| LLM plugin | ✅ Enabled | `sentinel.toml` [llm] enabled = true |

## Configuration Changes Applied

File: `/home/typemnm/sentinel/sentinel.toml`

| Field | Before | After | Source |
|-------|--------|-------|--------|
| `enabled` | `false` | `true` | gemma4 reference config |
| `api_timeout_secs` | `120` | `180` | gemma4 reference config (local inference is slower) |

Reference preset: `/home/typemnm/gemma4/sentinel-gemma4.toml`

## Endpoint Verification

Direct API test (2026-05-03):

```bash
curl -s http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gemma3:27b","messages":[{"role":"user","content":"Reply with valid JSON: {\"status\":\"ok\"}"}],"max_tokens":50}'
```

Response:
```json
{
  "id": "chatcmpl-624",
  "object": "chat.completion",
  "created": 1777790488,
  "model": "gemma3:27b",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "```json\n{\"status\":\"ok\"}\n```\n"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 19, "completion_tokens": 12, "total_tokens": 31}
}
```

**Result:** Model responds correctly. JSON generation works. Finish reason is `stop` (not truncated).

## Active Configuration Summary

```toml
[llm]
enabled = true
provider = "openai-compat"
api_base = "http://localhost:11434/v1"
model = "gemma3:27b"
api_key = ""                   # No auth needed for local Ollama
api_timeout_secs = 180         # Extended for local inference latency
max_tokens = 2048
temperature = 0.2
min_severity = "high"          # Only High/Critical findings sent to LLM
max_findings = 20
max_attacks_per_finding = 5
dry_run = false
max_evidence_chars = 4096      # Prompt injection mitigation
```

## Usage

```bash
# Run scan with LLM analysis enabled (uses sentinel.toml defaults)
./target/debug/sentinel --target https://example.com

# Alternatively, use the dedicated Gemma4 preset:
./target/debug/sentinel --config /home/typemnm/gemma4/sentinel-gemma4.toml \
  --target https://example.com --llm
```

## Notes

- `api_key` is intentionally empty — Ollama does not require authentication
- `temperature = 0.2` keeps payloads deterministic for reproducible bug reports
- `dry_run = false` means generated payloads will be executed during scans; set to `true` for safe preview
- `max_evidence_chars = 4096` limits evidence sent per finding to mitigate prompt injection
