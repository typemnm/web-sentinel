# Sentinel Improvement Spec

## Source
Derived from architect analysis of sentinel v0.1.0 (Rust web vulnerability scanner).

## Goals
Fix all identified bugs, security issues, performance problems, and dead code in priority order.

## Tasks (Priority Order)

### P0 — Security (must fix)
1. **Lua sandbox**: Remove `debug` library and `load` function from sandbox whitelist in `src/scripting/engine.rs`
2. **CVE version_lt**: Strip non-numeric suffixes (e.g. `-debian`) before parsing version components in `src/db/cve.rs`

### P1 — Bug Fixes
3. **Crawler DFS→BFS**: Replace `Vec` with `VecDeque` + `pop_front()` in `src/network/crawler.rs`
4. **get_no_redirect**: Store no-redirect client as a field in `HttpClient` instead of creating per-call in `src/network/http.rs`
5. **Hardcoded DB paths**: Make db paths configurable (derived from output dir or tempdir) in `src/core/orchestrator.rs`

### P2 — Performance
6. **Regex caching in dedup.rs**: Use `OnceLock<Regex>` for `normalize_title` regexes in `src/report/dedup.rs`
7. **Regex caching in evasion.rs**: Use `OnceLock<Regex>` or pre-compile regexes outside loops in `src/network/evasion.rs`

### P3 — Dead Code / Dependencies
8. **Remove `config` crate**: Remove unused `config = "0.14"` from `Cargo.toml`; either implement `sentinel.toml` loading or remove it
9. **Finding immutability**: Replace `push_str` mutation with new struct construction in `src/core/orchestrator.rs`

### Out of Scope (too large for this pass)
- `analyzer.rs` module split (1708 lines) — tracked as future work
- `sled` → SQLite migration — tracked as future work
- Concurrent crawler — tracked as future work

## Acceptance Criteria
- `cargo build --release` succeeds with no errors
- No new clippy warnings introduced
- All fixes verified by reading the changed code
