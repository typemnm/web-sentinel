# Sentinel 성능 개선 구현 방안

> 분석 기준 버전: 0.1.0
> 항목 수: 12개 (Critical 4 / High 3 / Medium 3 / Low 2) + **v0.1.1 신규 7개**
>
> **최종 업데이트: 2026-03-24**
> 아래 항목 중 상당수가 v0.1.0 개선 사이클에서 구현 완료 또는 부분 해소되었다.
> v0.1.1 사이클에서 정확도(FP 제거) 및 SPA 지원 개선 7건이 추가 구현되었다.
> 각 항목에 `[구현됨]`, `[부분 해소]`, `[미구현]` 상태를 표기한다.

---

## Critical

---

### ① 동일 URL에 중복 GET 요청 제거 — `[구현됨]`

> **상태**: `run()`에서 1회 GET한 `base_resp`를 패시브 체크에 참조 전달하고, `base_resp.elapsed_ms`를 `check_injections_multi()`의 target baseline으로 재사용하여 중복 GET 제거 완료.

**파일**: `src/network/analyzer.rs`

**현재 문제**

`ResponseAnalyzer::run()`이 같은 target에 최소 3번 독립 GET을 날린다.

```
check_security_headers()  → GET target   (line 61)
check_cookies()           → GET target   (line 229)
403 feedback loop         → GET target   (line 45)
```

세 함수 모두 동일한 응답 데이터(헤더 + 바디)를 필요로 한다. 타겟 응답이 200ms라면 이것만으로 400ms 이상 낭비된다.

**구현 방안**

`run()`에서 1회만 GET하고 `HttpResponse`를 참조로 전달한다. 헤더 전용 체크는 바디가 필요 없으므로 HEAD 요청 전략도 병행한다.

```rust
// analyzer.rs - 변경 전 run()
pub async fn run(&self, target: &str) -> Result<Vec<Finding>> {
    findings.extend(self.check_security_headers(target).await?);  // GET
    findings.extend(self.check_sqli(target).await?);
    findings.extend(self.check_open_redirect(target).await?);
    findings.extend(self.check_cookies(target).await?);           // GET (중복)
    // ...
    if let Ok(resp) = self.client.get(target).await { ... }       // GET (중복)
}

// analyzer.rs - 변경 후 run()
pub async fn run(&self, target: &str) -> Result<Vec<Finding>> {
    // 단 1회 요청, 재사용
    let base_resp = self.client.get(target).await?;

    findings.extend(self.check_security_headers(&base_resp));     // 참조만
    findings.extend(self.check_sqli(target).await?);              // URL 파라미터 조작 필요 → 별도 요청 유지
    findings.extend(self.check_open_redirect(target).await?);
    findings.extend(self.check_cookies(&base_resp));              // 참조만

    // 403 처리도 이미 받은 응답으로 판단
    if base_resp.status == 403 {
        if let Ok(Some(bypassed)) = try_403_bypass(&self.client, target).await { ... }
    }
}

// 시그니처 변경: URL → 이미 받은 응답 참조
async fn check_security_headers(&self, resp: &HttpResponse) -> Vec<Finding> { ... }
async fn check_cookies(&self, resp: &HttpResponse) -> Vec<Finding> { ... }
```

**헤더 전용 체크용 HEAD 메서드 추가** (`http.rs`)

```rust
/// 바디 없이 헤더만 필요한 경우 사용 (대역폭 절약)
pub async fn head(&self, url: &str) -> Result<HttpResponse> {
    let resp = self.inner.head(url).send().await?;
    HttpResponse::from_reqwest_head(resp).await
}

impl HttpResponse {
    async fn from_reqwest_head(resp: Response) -> Result<Self> {
        let url = resp.url().to_string();
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }
        Ok(Self { status, headers, body: String::new(), url })
    }
}
```

**기대 효과**: 타겟당 GET 요청 3→1회. RTT × 2 절약. 네트워크 대역폭 절반 이하.

---

### ② Phase 1(포트 스캔) + Phase 2(핑거프린팅) 병렬 실행 — `[구현됨]`

> **상태**: `tokio::join!`으로 Phase 1+2, Phase 4+5 병렬 실행 구현 완료. orchestrator.rs에서 확인 가능.

**파일**: `src/core/orchestrator.rs`

**현재 문제**

두 Phase가 완전히 독립적임에도 순차 실행된다.

```rust
// 현재: port_scan이 끝나야 fingerprint 시작
let open_ports = port_scanner.scan(&host).await?;  // 최대 3s × 포트수
let fp_result = fingerprinter.detect(...).await?;   // 별도 HTTP GET
```

포트 스캔은 TCP 연결 시도로 I/O bound, 핑거프린팅은 HTTP GET으로 I/O bound다. 둘 다 CPU를 점유하지 않으므로 겹쳐서 실행하지 않을 이유가 없다.

**구현 방안**

`tokio::join!`으로 두 작업을 동시 실행한다.

```rust
// orchestrator.rs
pub async fn run(&mut self) -> Result<()> {
    let target = self.ctx.config.target.clone();
    let host   = extract_host(&target);

    let http_client  = HttpClient::new(&self.ctx)?;
    let port_scanner = PortScanner::new(self.ctx.clone());
    let fingerprinter = Fingerprinter::new();

    // Phase 1 + 2 동시 실행
    let (ports_result, fp_result) = tokio::join!(
        async {
            if self.ctx.config.port_scan_enabled {
                port_scanner.scan(&host).await
            } else {
                Ok(vec![])
            }
        },
        fingerprinter.detect(&target, &http_client)
    );

    let open_ports = ports_result?;
    let fp_result  = fp_result?;

    // 이후 Phase 3, 4, 5, 6은 fp_result 의존이므로 순서 유지
    // ...
}
```

Phase 4(HTTP 체크) + Phase 5(Lua 스크립트)도 독립적이므로 같은 방식으로 묶을 수 있다.

```rust
// Phase 4 + 5 동시 실행
let scope = ScopeGuard::new(&self.ctx.config.scope);
let analyzer = ResponseAnalyzer::new(self.ctx.clone(), http_client.clone(), scope);

let mut engine = ScriptEngine::new(self.ctx.clone(), http_client.clone()).await?;

let (http_findings, script_findings) = tokio::join!(
    analyzer.run(&target),
    engine.run_all(&target)
);

findings.extend(http_findings?);
findings.extend(script_findings?);
```

**기대 효과**: Phase 1+2 합산 시간이 `max(port_scan, fingerprint)` 시간으로 단축. 전체 스캔 시간 20~40% 감소 예상.

---

### ③ SQLi 파라미터 체크 병렬화 — `[구현됨]`

> **상태**: `check_sqli`, `check_path_traversal`, `check_cmdi` 모두 파라미터별 `join_all` 병렬화 완료. 폼 인젝션도 `join_all` 적용.

**파일**: `src/network/analyzer.rs:132~175`

**현재 문제**

파라미터 수 × 페이로드 수(4)만큼 GET 요청이 직렬로 대기한다.

```rust
for (param_name, _) in &original_query {      // 직렬 루프
    for payload in payloads {                 // 직렬 루프
        self.client.get(&test_url).await?;    // 각각 블로킹 await
    }
}
// URL에 파라미터 5개면 → 20번 순차 요청
```

**구현 방안**

파라미터별로 태스크를 생성하고 `futures::future::join_all`로 동시 실행한다. `self` 참조를 넘기지 않으려면 필요한 값을 clone해서 move한다.

```rust
// Cargo.toml에 추가
// futures = "0.3"  (이미 있음)

use futures::future::join_all;

async fn check_sqli(&self, url: &str) -> Result<Vec<Finding>> {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let original_query: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if original_query.is_empty() {
            return Ok(vec![]);
        }

        // 파라미터별 태스크 생성
        let tasks: Vec<_> = original_query.iter().map(|(param_name, _)| {
            let client      = self.client.clone();
            let scope       = self.scope.clone();    // ScopeGuard에 Clone 구현 필요
            let param_name  = param_name.clone();
            let original_q  = original_query.clone();
            let url_str     = url.to_string();
            let mut base    = parsed.clone();

            async move {
                let mut findings = Vec::new();
                for payload in SQL_PAYLOADS {           // static으로 이동
                    // ... URL 조작 및 요청 로직 동일
                    // 요청들이 이제 진짜 동시에 실행됨
                }
                findings
            }
        }).collect();

        // 모든 파라미터 동시 실행
        let results = join_all(tasks).await;
        return Ok(results.into_iter().flatten().collect());
    }
    Ok(vec![])
}
```

`ScopeGuard`에 `Clone` derive 추가 (`scope.rs`):

```rust
#[derive(Clone)]
pub struct ScopeGuard {
    allowed_host: String,
}
```

**기대 효과**: `N_params × N_payloads` 직렬 → 파라미터 수만큼 병렬. 5개 파라미터 기준 4배 빠름.

---

### ④ Fingerprint 정규식 전역 1회 컴파일 — `[구현됨]`

> **상태**: `OnceLock` 패턴으로 fingerprint.rs 및 crawler.rs에서 정규식 캐싱 구현 완료.

**파일**: `src/network/fingerprint.rs:37~41`

**현재 문제**

```rust
pub fn new() -> Self {
    Self { patterns: build_patterns() }  // 매 스캔마다 Regex::new() ~20회 호출
}
```

`Regex::new()`는 NFA/DFA 컴파일을 수행하는 비싼 연산이다. 패턴이 바뀌지 않으므로 프로세스 수명 동안 1회만 하면 된다.

**구현 방안**

`std::sync::OnceLock`(Rust 1.70+, 의존성 추가 없음)을 사용한다.

```rust
// fingerprint.rs
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<FingerprintPattern>> = OnceLock::new();

impl Fingerprinter {
    pub fn new() -> Self {
        // 첫 호출에만 build_patterns() 실행, 이후 캐시된 참조 반환
        let _ = PATTERNS.get_or_init(build_patterns);
        Self { /* patterns 필드 제거 가능, PATTERNS 직접 참조 */ }
    }

    pub async fn detect(&self, url: &str, client: &HttpClient) -> Result<FingerprintResult> {
        let patterns = PATTERNS.get().expect("patterns not initialized");
        // ... 이후 동일
    }
}
```

또는 구조체 필드를 유지하면서 `&'static` 참조로 변경:

```rust
pub struct Fingerprinter {
    patterns: &'static Vec<FingerprintPattern>,
}

impl Fingerprinter {
    pub fn new() -> Self {
        Self {
            patterns: PATTERNS.get_or_init(build_patterns),
        }
    }
}
```

**기대 효과**: 첫 스캔 이후 `Fingerprinter::new()` 비용이 힙 할당 없이 포인터 반환 수준으로 감소. 연속 스캔(배치 모드) 시 특히 효과적.

---

## High

---

### ⑤ SQLi 응답 바디 `to_lowercase()` 최적화 — `[구현됨]`

> **상태**: `memchr` 크레이트 도입 완료. `memmem_find_icase()`가 SIMD 가속 `memchr::memmem::find()`를 사용하여 바이트 수준 검색 수행. 8KB 이하는 스택 버퍼, 이상은 힙 할당.

**파일**: `src/network/analyzer.rs:153`

**현재 문제**

```rust
if let Ok(resp) = self.client.get(&test_url).await {
    let body_lower = resp.body.to_lowercase();  // 요청마다 전체 바디 복사 할당
    for sig in sql_errors {
        if body_lower.contains(sig) { ... }
    }
}
```

바디가 50KB면 요청마다 50KB 힙 할당이 발생한다. `N_params × N_payloads` 요청이면 총 `N × 4 × 50KB` 할당.

**구현 방안 1 — `memchr` 크레이트 사용 (권장)**

대소문자 무관 검색을 별도 할당 없이 수행한다.

```toml
# Cargo.toml
memchr = "2"
```

```rust
use memchr::memmem;

// 시그니처를 소문자로 미리 선언 (컴파일 타임 상수)
static SQL_ERROR_SIGS: &[&[u8]] = &[
    b"you have an error in your sql syntax",
    b"unclosed quotation mark",
    b"quoted string not properly terminated",
    b"pg_query()",
    b"sqlstate",
    b"ora-01756",
];

// 응답 바디는 bytes로 검색 (할당 없음)
let body_bytes = resp.body.as_bytes();
for sig in SQL_ERROR_SIGS {
    // memmem은 Boyer-Moore-Horspool로 case-sensitive 검색
    // 시그니처를 소문자로 유지하고 바디도 슬라이딩 비교
    if memmem::find(body_bytes, sig).is_some() { ... }
}
```

**구현 방안 2 — 청크 단위 lower 검색**

전체 바디 대신 처음 4KB만 lowercase 변환한다. SQL 에러는 대부분 응답 초반에 위치한다.

```rust
let check_range = resp.body.len().min(4096);
let body_lower = resp.body[..check_range].to_lowercase();
```

**기대 효과**: 요청당 힙 할당 50KB → 0 (memchr) 또는 4KB (청크). 고부하 시 GC pressure 감소.

---

### ⑥ Lua 스크립트 병렬 실행 — `[구현됨]`

> **상태**: `spawn_blocking` + `join_all`로 Lua 스크립트 28개 병렬 실행 구현 완료. engine.rs에서 확인 가능.

**파일**: `src/scripting/engine.rs:38~46`

**현재 문제**

```rust
for entry in entries.flatten() {
    self.run_script(&path, target).await;  // 순서대로 대기
}
// 스크립트 10개, 각 HTTP 요청 1개 → 10 RTT 직렬
```

각 Lua 스크립트는 독립적인 `Lua` VM 인스턴스를 생성한다. `Lua`는 `!Send`이므로 tokio의 async task로 직접 spawn할 수 없고 `spawn_blocking`을 사용해야 한다.

**구현 방안**

스크립트별로 `tokio::task::spawn_blocking` 스레드를 생성하고 `join_all`로 수거한다.

```rust
use futures::future::join_all;

pub async fn run_all(&mut self, target: &str) -> Result<Vec<Finding>> {
    let scripts_dir = self.ctx.config.scripts_dir.clone();
    let entries = std::fs::read_dir(&scripts_dir)?;

    // 스크립트 경로 수집
    let lua_files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lua"))
        .collect();

    // 각 스크립트마다 독립 blocking 스레드에서 실행
    let findings_ref = self.findings.clone();
    let tasks: Vec<_> = lua_files.into_iter().map(|path| {
        let client     = self.client.clone();
        let target_str = target.to_string();
        let findings   = findings_ref.clone();
        let ctx        = self.ctx.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<Finding>> {
            // spawn_blocking 스레드 내부: Lua는 !Send지만 여기선 단일 스레드
            let source = std::fs::read_to_string(&path)?;
            let lua    = mlua::Lua::new();

            // sandbox setup (setup_sandbox를 self 없이 순수 함수로 분리 필요)
            setup_sandbox_static(&lua, &target_str, &client, &ctx)?;

            let result: mlua::Value = lua.load(&source)
                .eval()
                .map_err(|e| anyhow::anyhow!("Lua: {}", e))?;

            let mut local_findings = Vec::new();
            if let mlua::Value::Table(tbl) = result {
                // table_to_finding 로직
            }
            Ok(local_findings)
        })
    }).collect();

    // 모든 스크립트 완료 대기
    let results = join_all(tasks).await;
    for res in results {
        match res {
            Ok(Ok(f))  => self.findings.lock().await.extend(f),
            Ok(Err(e)) => warn!("Script error: {:#}", e),
            Err(e)     => warn!("Script panic: {:#}", e),
        }
    }

    Ok(self.findings.lock().await.clone())
}
```

`setup_sandbox`를 `self` 없이 호출 가능한 자유 함수로 분리하는 리팩토링이 선행 필요하다.

**기대 효과**: 스크립트 N개 직렬 → 병렬. 10개 스크립트 × 200ms HTTP → 200ms (이론상).

---

### ⑦ `try_403_bypass` 헤더 동시 시도 — `[구현됨]`

> **상태**: `select_ok`로 bypass 헤더 + 경로 변형 11개 기법 동시 시도 구현 완료. analyzer.rs에서 확인 가능.

**파일**: `src/network/analyzer.rs:277~294`

**현재 문제**

```rust
for (k, v) in bypass_headers {
    let resp = client.get_with_headers(url, &[(*k, *v)]).await?;  // 순서대로
    if resp.status != 403 { return Ok(Some(resp)); }
}
// 4개 헤더 × RTT → 최대 4 RTT 직렬
```

**구현 방안**

`futures::future::select_ok`로 4개 요청을 동시에 발사하고 첫 번째 non-403 응답을 반환한다.

```rust
use futures::future::select_ok;

pub async fn try_403_bypass(
    client: &HttpClient,
    url: &str,
) -> Result<Option<HttpResponse>> {
    static BYPASS_HEADERS: &[(&str, &str)] = &[
        ("X-Forwarded-For",          "127.0.0.1"),
        ("X-Original-URL",           "/"),
        ("X-Custom-IP-Authorization","127.0.0.1"),
        ("X-Forwarded-Host",         "localhost"),
    ];

    // 4개 요청을 Future로 생성
    let futures: Vec<_> = BYPASS_HEADERS
        .iter()
        .map(|(k, v)| {
            let client = client.clone();
            let url    = url.to_string();
            let k      = *k;
            let v      = *v;
            Box::pin(async move {
                let resp = client.get_with_headers(&url, &[(k, v)]).await?;
                if resp.status != 403 {
                    Ok(resp)
                } else {
                    Err(anyhow::anyhow!("still 403"))
                }
            })
        })
        .collect();

    // 첫 번째 성공(non-403) 응답만 취하고 나머지는 drop
    match select_ok(futures).await {
        Ok((resp, _remaining)) => Ok(Some(resp)),
        Err(_)                 => Ok(None),
    }
}
```

**기대 효과**: bypass 성공 시 응답 시간이 `max(4개 RTT)` → `min(4개 RTT)`로 단축. 평균 4배 빠름.

---

## Medium

---

### ⑧ Connection Pool 크기를 스레드 수에 비례 조정 — `[구현됨]`

> **상태**: `pool_max_idle_per_host`를 `(threads / 2).clamp(10, 100)`으로 동적 조정, `pool_idle_timeout(90s)` 및 `tcp_keepalive(30s)` 추가 완료. http.rs에서 확인 가능.

**파일**: `src/network/http.rs:38`

**현재 문제**

```rust
.pool_max_idle_per_host(10)  // 기본값 하드코딩
```

`--threads 50` 기본값에서 동시 요청이 50개인데 idle pool이 10이면 40개는 매번 새 TCP 연결을 맺는다. TLS 핸드셰이크까지 포함하면 연결당 수십~수백ms 추가 비용이 발생한다.

**구현 방안**

`pool_max_idle_per_host`를 `threads` 수와 연동한다.

```rust
impl HttpClient {
    pub fn new(ctx: &ScanContext) -> Result<Self> {
        let threads = ctx.config.threads;
        // idle pool = threads / 2, 최소 10, 최대 100
        let pool_size = (threads / 2).clamp(10, 100);

        let client = Client::builder()
            .timeout(Duration::from_secs(ctx.config.timeout_secs))
            .pool_max_idle_per_host(pool_size)
            .pool_idle_timeout(Duration::from_secs(90))  // 추가: idle 연결 유지 시간
            .tcp_keepalive(Duration::from_secs(30))       // 추가: TCP keepalive
            .user_agent(ua)
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self { inner: client })
    }
}
```

**기대 효과**: 고부하 스캔(`--threads 100`)에서 연결 재사용률 향상. TLS 재핸드셰이크 비용 제거.

---

### ⑨ 헤더 전용 체크에서 바디 로드 스킵 — `[부분 해소]`

> **상태**: `http.head()` 메서드 구현 완료 (Lua API에서 사용 가능). 엔진 내부에서 패시브 체크에 HEAD 사용은 ①과 병행하여 향후 적용.

**파일**: `src/network/http.rs:97~109`

**현재 문제**

```rust
async fn from_reqwest(resp: Response) -> Result<Self> {
    // ...
    let body = resp.text().await?;  // 항상 전체 바디 읽기
}
```

`check_security_headers`와 `check_cookies`는 응답 헤더만 필요하다. 바디가 1MB인 정적 페이지를 스캔하면 불필요한 1MB 네트워크 수신 + 메모리 할당이 발생한다.

**구현 방안**

두 가지 요청 모드를 제공한다.

```rust
/// 헤더 + 바디 모두 필요한 경우 (기존)
pub async fn get(&self, url: &str) -> Result<HttpResponse> { ... }

/// 헤더만 필요한 경우 (바디 수신 생략)
pub async fn head(&self, url: &str) -> Result<HttpResponse> {
    let resp = self.inner
        .request(reqwest::Method::HEAD, url)
        .send()
        .await?;
    HttpResponse::from_reqwest_headers_only(resp).await
}

impl HttpResponse {
    /// 바디 없이 헤더만 파싱 (할당 최소화)
    async fn from_reqwest_headers_only(resp: Response) -> Result<Self> {
        let url    = resp.url().to_string();
        let status = resp.status().as_u16();
        let mut headers = HashMap::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }
        // resp는 여기서 drop → 바디 수신 안 함
        Ok(Self { status, headers, body: String::new(), url })
    }
}
```

그리고 ① 번 개선과 연계해서, `check_security_headers`와 `check_cookies`가 이미 공유 응답을 받으면 HEAD 요청 자체가 불필요해진다.

> ① 번 개선이 적용되면 이 항목은 자동 해소된다. ①이 적용되지 않는 경우의 독립 대안이다.

---

### ⑩ `req.try_clone().unwrap()` 패닉 제거 — `[구현됨]`

> **상태**: 재시도 루프에서 매 시도마다 새 RequestBuilder를 구성하도록 변경 완료. try_clone() 제거됨.

**파일**: `src/network/http.rs:59`

**현재 문제**

```rust
match req.try_clone().unwrap().send().await {
```

`RequestBuilder::try_clone()`은 스트리밍 바디(Body가 stream인 경우)에서 `None`을 반환한다. `unwrap()`이 런타임 패닉으로 이어진다. 현재는 GET만 재시도하므로 문제없지만 POST 재시도가 추가되면 즉시 터진다.

**구현 방안**

```rust
pub async fn get_with_headers(
    &self,
    url: &str,
    extra_headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let mut last_err = None;

    for attempt in 0..3u8 {
        // 매 시도마다 새로 빌더를 구성 (clone 불필요)
        let mut req = self.inner.get(url);
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }

        match req.send().await {
            Ok(resp) => {
                debug!("GET {} -> {}", url, resp.status());
                return HttpResponse::from_reqwest(resp).await;
            }
            Err(e) if attempt < 2 => {
                last_err = Some(e);
                let delay = Duration::from_millis(300 * (attempt as u64 + 1));
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Err(last_err.unwrap().into())
}
```

`RequestBuilder`는 `send()`에서 consume되므로 매 재시도마다 새로 만드는 것이 올바른 패턴이다. `try_clone()` 자체를 제거한다.

**기대 효과**: 잠재적 패닉 제거. POST 재시도 지원 가능.

---

## Low

---

### ⑪ Findings 수집 구조를 Mutex-free로 전환 — `[구현됨]`

> **상태**: 각 Phase가 독립 `Vec<Finding>`을 반환하고 마지막에 병합하는 구조로 전환 완료. Mutex 제거됨. orchestrator.rs에서 확인 가능.

**파일**: `src/core/orchestrator.rs:20`

**현재 문제**

```rust
findings: Arc<Mutex<Vec<Finding>>>,
```

Phase들이 직렬인 현재는 contention이 없다. 하지만 ② 번 개선(Phase 병렬화)을 적용하면 여러 Phase가 동시에 `lock().await`를 호출해 contention이 발생한다.

**구현 방안**

각 Phase가 독립적인 `Vec<Finding>`을 반환하도록 시그니처를 변경하고, 마지막에 한 번만 합산한다. Mutex 자체를 제거한다.

```rust
pub struct Orchestrator {
    ctx: ScanContext,
    // findings: Arc<Mutex<Vec<Finding>>>,  ← 제거
}

pub async fn run(&mut self) -> Result<()> {
    // ...

    // 각 Phase는 Vec<Finding> 반환
    let (port_findings, fp_result) = tokio::join!(
        async { phase_ports(...).await },
        async { phase_fingerprint(...).await }
    );

    let (http_findings, script_findings) = tokio::join!(
        analyzer.run(&target),
        engine.run_all(&target)
    );

    // 마지막에 한 번만 병합 (lock 없음)
    let mut all_findings = Vec::new();
    all_findings.extend(port_findings?);
    all_findings.extend(fp_result?.into_findings());
    all_findings.extend(http_findings?);
    all_findings.extend(script_findings?);

    // CVE findings 등 직렬로 추가
    all_findings.extend(cve_findings);

    // 리포트 작성
    writer.write(&target, &all_findings).await?;
}
```

**기대 효과**: Mutex lock/unlock 오버헤드 제거. Phase 병렬화 후 contention 근본 해소.

---

### ⑫ `header_name.to_lowercase()` 불필요 할당 제거 — `[구현됨]`

> **상태**: CRLF 헤더 검사에서 case-insensitive 비교로 전환 완료. 불필요한 할당 제거됨.

**파일**: `src/network/analyzer.rs:232`

**현재 문제**

```rust
for (header_name, header_value) in &resp.headers {
    if header_name.to_lowercase() != "set-cookie" {  // 매 헤더마다 String 할당
        continue;
    }
```

`HttpResponse::from_reqwest()`에서 헤더를 저장할 때 `k.to_string()`을 사용하는데, reqwest의 `HeaderName`은 내부적으로 소문자로 정규화되어 있다. 즉 `header_name`은 이미 소문자다.

**구현 방안**

`to_lowercase()` 호출을 제거하고 직접 비교한다.

```rust
// 변경 전
if header_name.to_lowercase() != "set-cookie" { continue; }

// 변경 후 (할당 없음)
if header_name != "set-cookie" { continue; }
```

`from_reqwest`에서 소문자 저장을 코드로 명시적으로 보장하려면:

```rust
async fn from_reqwest(resp: Response) -> Result<Self> {
    // ...
    for (k, v) in resp.headers() {
        // k.as_str()은 reqwest에서 보장된 소문자 ASCII
        headers.insert(k.as_str().to_string(), v.to_str().unwrap_or("").to_string());
    }
}
```

**기대 효과**: 헤더당 불필요한 String 할당 제거. 미미하나 헤더가 많은 응답에서 누적 효과 있음.

---

## 구현 상태 요약

| 항목 | 예상 효과 | 상태 |
|------|-----------|------|
| ① 중복 GET 제거 | RTT × 2 절약 | **구현됨** — base_resp 참조 + elapsed_ms 재사용 |
| ② Phase 병렬화 | 스캔 시간 20~40% 감소 | **구현됨** — tokio::join! |
| ③ SQLi 병렬화 | 파라미터 수 비례 향상 | **구현됨** — 파라미터별 join_all |
| ④ Regex OnceLock | 재컴파일 비용 제거 | **구현됨** — OnceLock 패턴 |
| ⑤ memchr 검색 | 메모리 할당 압박 감소 | **구현됨** — SIMD 가속 memchr::memmem |
| ⑥ Lua 병렬화 | 스크립트 수 비례 향상 | **구현됨** — spawn_blocking |
| ⑦ 403bypass 병렬 | 4→1 RTT | **구현됨** — select_ok |
| ⑧ Pool 크기 조정 | 고부하 시 연결 재사용 | **구현됨** — (threads/2).clamp(10,100) |
| ⑨ HEAD 요청 | 대역폭 절약 | **부분 해소** — head() 메서드 추가 |
| ⑩ try_clone 패닉 제거 | 안전성 확보 | **구현됨** — 매 시도 새 빌더 |
| ⑪ Mutex 제거 | contention 근본 해소 | **구현됨** — Vec 반환 + 마지막 병합 |
| ⑫ lowercase 제거 | 미미한 할당 제거 | **구현됨** — case-insensitive 비교 |

**12개 항목 중 11개 구현 완료, 1개 부분 해소 (⑨ — ①로 대부분 해소).**

---

## v0.1.1 정확도 및 SPA 지원 개선 (2026-03-24)

> 7개 항목 모두 구현 완료. OWASP Juice Shop (Angular SPA) 스캔 기준
> 오탐 18건 → 0건, 탐지된 API 엔드포인트 0개 → 15개 이상.

---

### ⑬ SPA JS 엔드포인트 추출 — `[구현됨]`

> **상태**: 크롤러가 `<script src="...">` 태그에서 JS 파일을 최대 10개 가져와
> API 경로 패턴(`/api/`, `/rest/`, `/v1/`, `/graphql` 등)을 추출한다.

**파일**: `src/network/crawler.rs`

**이전 문제**

SPA(Single Page Application)는 HTML에 링크가 거의 없고 모든 라우팅이 JS에서 처리된다.
기존 크롤러는 `.js` 파일을 `is_static_resource()`로 무시하여 API 엔드포인트를 전혀 발견하지 못했다.

```
# Juice Shop (Angular) 기존 결과
Crawl complete: 0 links, 0 forms discovered
```

**구현 내용**

1. `SCRIPT_SRC_RE`: `<script src="...">` 태그에서 JS 파일 URL 추출
2. `JS_STRING_API_RE`: JS 파일 내 API 경로 패턴 추출 (28개 접두사)
3. JS 파일 최대 10개 fetch → `fetch/axios` regex + API path regex 동시 적용

```rust
// 새로 추가된 정적 regex
static SCRIPT_SRC_RE: OnceLock<Regex> = OnceLock::new();     // <script src="...">
static JS_STRING_API_RE: OnceLock<Regex> = OnceLock::new();   // "/api/...", "/rest/..." 등
```

**결과**: Juice Shop에서 `/rest/user/login`, `/api/Users`, `/api/Products`, `/api/Challenges` 등 15개 이상의 API 엔드포인트가 자동 발견되어 인젝션 테스트 대상에 포함됨.

---

### ⑭ SSTI 오탐 방지 — `[구현됨]`

> **상태**: Lua `ssti_probe.lua`의 페이로드를 `{{7*7}}`→`{{913*773}}`로 변경하고
> 베이스라인 체크를 추가하여 페이지에 자연 존재하는 숫자로 인한 오탐을 제거.

**파일**: `scripts/ssti_probe.lua`

**이전 문제**

`{{7*7}}` → `49` 검사에서, 페이지 내 자연적으로 존재하는 "49" (예: Angular 빌드 해시, CSS 속성 등)와 매칭되어 오탐이 발생했다.

**구현 내용**

1. 모든 SSTI 프로브를 `913*773=705649` 고유 수학식으로 변경 (Rust 분석기와 동일)
2. 스크립트 시작 시 `TARGET`에 GET 요청 → `baseline_body` 확보
3. `expected` 값이 `baseline_body`에 이미 존재하면 해당 프로브 건너뜀

```lua
-- 변경 전 (오탐 발생)
{payload = "{{7*7}}", expected = "49", engine = "Jinja2/Twig/Nunjucks"},

-- 변경 후
{payload = "{{913*773}}", expected = "705649", engine = "Jinja2/Twig/Nunjucks"},
```

**결과**: Juice Shop SSTI 오탐 1건 → 0건 제거. 실제 SSTI 취약점(`/render` Handlebars)은 정확히 탐지.

---

### ⑮ 백업 파일 SPA 오탐 제거 — `[구현됨]`

> **상태**: `backup_files.lua`에 SPA 감지 로직을 추가하여, 존재하지 않는 경로에도
> 200+HTML을 반환하는 SPA에서 백업 파일 오탐을 완전히 제거.

**파일**: `scripts/backup_files.lua`

**이전 문제**

SPA(Angular, React 등)는 클라이언트 사이드 라우팅을 위해 모든 경로에 200 + HTML 셸을 반환한다.
`/backup.zip`, `/dump.sql` 등에 대해서도 200이 반환되어 15건 이상의 오탐이 발생했다.

**구현 내용**

1. 랜덤 존재하지 않는 경로에 GET → 200이면 SPA로 판정
2. 각 백업 파일 응답의 `Content-Type`과 본문 시작 부분 검사
3. SPA이고 응답이 HTML이면 스킵 (진짜 백업 파일은 바이너리/텍스트)

```lua
local baseline = http.get(TARGET .. "/nonexistent_sentinel_check_" .. tostring(math.random(100000, 999999)))
if baseline and baseline.status == 200 then
    baseline_is_html = true  -- SPA 감지
end
```

**결과**: Juice Shop에서 백업 파일 오탐 15건 → 0건.

---

### ⑯ .htaccess/.htpasswd 시그니처 정밀화 — `[구현됨]`

> **상태**: `.htpasswd` 탐지 시그니처를 `":"` (모든 HTML에 매칭) →
> `"$apr1$"`, `"{SHA}"`, `"$2y$"` 해시 패턴으로 변경.

**파일**: `scripts/htaccess_exposure.lua`

**이전 문제**

`.htpasswd` 탐지에 `":"` (콜론) 시그니처를 사용하여, 모든 HTML 페이지에 매칭되었다.
SPA에서는 `.htpasswd` 경로에도 HTML 셸이 반환되어 오탐이 발생.

**구현 내용**

1. `":"` → `"$apr1$"`, `"{SHA}"`, `"$2y$"` (실제 htpasswd 해시 포맷)
2. 추가로 응답 본문 시작 부분의 HTML 태그 검사

**결과**: htaccess 오탐 1건 (`.htpasswd` 크리티컬) → 0건.

---

### ⑰ Django 핑거프린트 오탐 수정 — `[구현됨]`

> **상태**: Django 탐지 패턴에서 `X-Frame-Options: SAMEORIGIN` 헤더 매칭을 제거하고,
> 본문 기반 시그니처(`csrfmiddlewaretoken`, `django.contrib`)만 사용하도록 변경.

**파일**: `src/network/fingerprint.rs`

**이전 문제**

`X-Frame-Options: SAMEORIGIN` 헤더는 Django 외에도 많은 프레임워크/서버가 설정한다.
Juice Shop(Express/Angular)에서 이 헤더가 존재하여 "Django detected"로 오탐이 발생했다.

**구현 내용**

```rust
// 변경 전 (오탐 유발)
add_pattern!("Django", "Framework",
    headers: ["x-frame-options" => r"SAMEORIGIN"],
    body: [r"csrfmiddlewaretoken"]);

// 변경 후
add_pattern!("Django", "Framework",
    headers: [],
    body: [r"csrfmiddlewaretoken", r"django\.contrib|__django_"]);
```

**결과**: Juice Shop에서 Django 오탐 → 제거.

---

### ⑱ 프레임워크 핑거프린트 확장 — `[구현됨]`

> **상태**: Angular, React, Vue.js, Flask 탐지 패턴을 추가하여
> SPA 및 Python 프레임워크 식별 범위를 확장.

**파일**: `src/network/fingerprint.rs`

**구현 내용**

```rust
add_pattern!("Flask", "Framework",
    headers: [], body: [r"Werkzeug|flask\.pocoo\.org|flask_"]);
add_pattern!("Angular", "Framework",
    headers: [], body: [r"ng-version=|ng-app|angular\.min\.js|ng-controller"]);
add_pattern!("React", "Framework",
    headers: [], body: [r"react\.production\.min\.js|data-reactroot|_reactRootContainer"]);
add_pattern!("Vue.js", "Framework",
    headers: [], body: [r"vue\.min\.js|vue\.runtime|v-cloak|__vue__"]);
```

**결과**: 기존 14개 → 18개 핑거프린트 패턴. Juice Shop에서 Angular 정확 탐지.

---

### ⑲ prototype_pollution.lua 샌드박스 호환 — `[구현됨]`

> **상태**: `os.clock()` 호출 → `math.random()` 대체.
> Lua 샌드박스에서 `os` 모듈이 nil로 설정되어 스크립트가 크래시하던 문제 해결.

**파일**: `scripts/prototype_pollution.lua`

**구현 내용**

```lua
-- 변경 전 (크래시)
local marker = "SENTINEL_PP_" .. tostring(os.clock()):gsub("%.", "")

-- 변경 후
local marker = "SENTINEL_PP_" .. tostring(math.random(100000, 999999))
```

**결과**: 프로토타입 오염 탐지 스크립트가 정상 동작.

---

## v0.1.1 구현 상태 요약

| 항목 | 분류 | 효과 | 상태 |
|------|------|------|------|
| ⑬ SPA JS 엔드포인트 추출 | 탐지 범위 확대 | SPA 앱에서 API 15개+ 자동 발견 | **구현됨** |
| ⑭ SSTI 오탐 방지 | 정확도 향상 | `49` 자연 존재 오탐 제거 | **구현됨** |
| ⑮ 백업 파일 SPA 오탐 | 정확도 향상 | SPA 오탐 15건 제거 | **구현됨** |
| ⑯ htaccess 시그니처 정밀화 | 정확도 향상 | 범용 시그니처 오탐 제거 | **구현됨** |
| ⑰ Django FP 오탐 수정 | 정확도 향상 | 헤더 기반 오탐 제거 | **구현됨** |
| ⑱ 프레임워크 핑거프린트 확장 | 탐지 범위 확대 | 4개 프레임워크 추가 | **구현됨** |
| ⑲ prototype_pollution 수정 | 버그 수정 | 스크립트 크래시 해결 | **구현됨** |

**v0.1.0 + v0.1.1 합산: 19개 항목 중 18개 구현 완료, 1개 부분 해소.**
