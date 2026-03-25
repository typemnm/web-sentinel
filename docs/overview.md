# Project Sentinel — 개요 문서

> CERT용 웹 취약점 진단 소프트웨어
> 버전: 0.1.0 | 언어: Rust | 라이선스: MIT

---

## 1. 배경 및 목적

### 왜 만들었나

기존 오픈소스 스캐너들은 각자 한계가 있다.

| 도구 | 강점 | 한계 |
|------|------|------|
| Nuclei | 빠른 템플릿 기반 스캔 | YAML 정적 규칙, DOM 분석 불가 |
| Feroxbuster | 고속 디렉터리 브루트포스 | 응답 분석 없는 맹목적 탐색 |
| OWASP ZAP / Burp | 깊은 분석, 검증된 품질 | JVM 기반 고자원 소비, CLI 자동화 어려움 |

Sentinel은 이 세 도구의 장점을 하나로 통합한다.
**Rust의 성능** + **헤드리스 브라우저의 정밀도** + **Lua 스크립트의 확장성**이 핵심 전제다.

### 사용 대상

- CERT(Computer Emergency Response Team) 소속 진단 인력
- 화이트햇 침투 테스트 수행자
- 승인된 대상에 대한 자동화 진단이 필요한 보안 엔지니어

> **중요**: Sentinel은 반드시 명시적으로 승인된 대상에만 사용해야 한다.
> 스코프 밖 URL은 자동으로 차단되며, 맹목적 퍼징은 설계상 포함되지 않는다.

---

## 2. 핵심 설계 원칙

### 2.1 하이브리드 스캔

두 개의 스캔 레이어를 병렬로 운영한다.

```
Fast Layer  ─── reqwest (HTTP/1.1 + HTTP/2, Connection Pool)
                 └─ 헤더 분석, SQLi 탐지, 쿠키 검사, 리디렉션 추적

Deep Layer  ─── headless_chrome (DevTools Protocol)
                 └─ DOM 조작, JS 실행 감지, Reflected XSS 확인
```

### 2.2 피드백 루프

단순 "요청 → 결과" 구조가 아니라, 응답을 분석해 다음 공격을 변형한다.

```
Phase A (패시브)
    └─ base_resp 1회 GET → 보안 헤더 / CORS / 쿠키 / Mixed Content / 정보 유출

Phase B (능동, 병렬 — tokio::join!)
    ├─ SQLi (에러 기반 14종 + Time-based blind, 베이스라인 기반) → join_all 파라미터별
    │       WAF evasion: fast 3종 / --thorough 시 9종 인코딩 변환 적용
    ├─ Path Traversal → 16개 페이로드 (double-encode, null-byte, UTF-8 overlong 등)
    ├─ Command Injection → echo-based + time-based (baseline + 4000ms)
    ├─ SSTI → 6개 엔진 (고유값 913×773=705649 사용, 오탐 방지)
    ├─ CRLF Injection → 헤더 주입 확인 (case-insensitive)
    └─ Open Redirect → Location 헤더 직접 검사 (no-follow), 리디렉션 파라미터 7종

Phase C
    ├─ HTTP Method 검사 (OPTIONS → TRACE/PUT/DELETE)
    └─ 403 Bypass (5개 헤더 + 6개 경로 변형 → select_ok 경쟁)
```

### 2.3 Turing-Complete 확장

Lua 스크립트로 재컴파일 없이 새로운 진단 로직을 추가한다.
샌드박스 환경(io/os 차단)에서 `spawn_blocking` 병렬 실행되어 안전성과 성능을 동시에 보장한다.

### 2.4 완전 내장형

외부 데이터베이스 서버 없이 동작한다.

- **sled**: 스캔 진행 상태 영속화 (방문 URL, 스캔 단계)
- **SQLite (rusqlite)**: CVE 데이터베이스 (번들 빌드)

---

## 3. 아키텍처

### 3.1 디렉터리 구조

```
sentinel/
├── .github/
│   └── workflows/
│       ├── ci.yml           # Push/PR: fmt → clippy → test → release 빌드
│       └── release.yml      # v* 태그: 멀티 플랫폼 바이너리 → GitHub Release
├── src/
│   ├── main.rs              # CLI 진입점 (clap) — auth/crawl/thorough 옵션 포함
│   ├── core/
│   │   ├── scanner.rs       # ScanConfig, ScanContext, Finding, AuthMethod 타입 정의
│   │   └── orchestrator.rs  # 6개 Phase 조율 + tech→vuln linking + dedup 통합
│   ├── network/
│   │   ├── http.rs          # reqwest 래퍼 (재시도, governor 레이트리미터, 동적 풀, auth)
│   │   ├── port.rs          # 비동기 TCP 포트 스캐너
│   │   ├── fingerprint.rs   # Wappalyzer 스타일 기술 스택 탐지 (OnceLock 패턴 캐시)
│   │   ├── analyzer.rs      # 응답 분석 (SQLi/SSTI/CMDi/Traversal/CRLF/Redirect + WAF evasion)
│   │   ├── crawler.rs       # BFS 재귀 크롤러 (설정 가능한 depth/max_urls, JS 엔드포인트 추출)
│   │   ├── evasion.rs       # WAF 우회 모듈 (9개 인코딩 전략, fast/thorough 2단계)
│   │   └── scope.rs         # 스코프 가드 (out-of-scope URL 차단)
│   ├── db/
│   │   ├── cve.rs           # CVE SQLite DB (검색, 삽입)
│   │   └── state.rs         # sled 기반 스캔 상태 영속화
│   ├── scripting/
│   │   └── engine.rs        # Lua VM (mlua), 샌드박스, spawn_blocking 병렬 실행
│   ├── browser/
│   │   ├── controller.rs    # Chrome 실행/탭 관리
│   │   └── xss.rs           # DOM XSS (alert + MutationObserver + 8 polyglot 페이로드)
│   └── report/
│       ├── json.rs          # JSON 리포트 직렬화
│       └── dedup.rs         # Finding 중복 제거 (동일 URL 병합 + 크로스 URL 집계)
├── scripts/                 # Lua 플러그인 28개 (SSRF, SSTI, JWT, NoSQL, XXE, IDOR 등)
├── Dockerfile               # Multi-stage 빌드 (builder → runtime+Chromium)
├── docker-compose.yml       # 로컬 실행 + Juice Shop 테스트 프로파일
├── .dockerignore
├── Makefile                 # build / release / test / lint / install / docker
├── sentinel.toml            # 기본 설정 파일
└── docs/                   # 이 문서들
```

### 3.2 스캔 실행 흐름

```
CLI 파싱 (clap) — auth/crawl/thorough 옵션 처리
    │
    ▼
Orchestrator::run()
    │
    ├─ [병렬] Phase 1 + Phase 2  ← tokio::join!
    │   ├─ Phase 1: 포트 스캔 (비동기 TCP, 29개 공통 포트)
    │   └─ Phase 2: HTTP 핑거프린팅
    │               (웹서버 / CMS / 프레임워크 / 언어 탐지, OnceLock 정규식 캐시)
    │
    ├─ Phase 3: CVE 상관관계 분석
    │           (탐지된 기술 스택 → SQLite CVE DB 조회)
    │
    ├─ Phase 3.5: 재귀 크롤링 (BFS, 설정 가능 depth/max_urls)
    │             (HTML 링크/폼 추출 + JS 엔드포인트 발견 → 스코프 필터)
    │
    ├─ [병렬] Phase 4 + Phase 5  ← tokio::join!
    │   ├─ Phase 4: HTTP 취약점 점검
    │   │   ├─ [패시브] 보안 헤더 6종 / CORS / 쿠키 / Mixed Content / 정보 유출 / 본문 패턴
    │   │   ├─ [능동, 병렬] SQLi (에러+Blind+베이스라인) / Path Traversal (16종) /
    │   │   │                CMDi / SSTI (6 엔진) / CRLF / Open Redirect (no-follow)
    │   │   │                — WAF evasion 적용 (fast 3종 / --thorough 시 9종)
    │   │   ├─ [크롤 연동] 발견된 URL 파라미터 인젝션 + 폼 POST 인젝션 (join_all 병렬)
    │   │   ├─ [파라미터 추측] param-less URL에 14개 공통 + 12개 SSTI 파라미터 프로빙
    │   │   ├─ HTTP Method 검사 (OPTIONS)
    │   │   └─ 403 Bypass (5개 헤더 + 6개 경로 변형, select_ok 경쟁)
    │   └─ Phase 5: Lua 스크립트 실행 (28개)
    │               (scripts/*.lua 파일 → spawn_blocking 병렬)
    │
    ├─ Phase 6: 헤드리스 브라우저 XSS 탐지 (--browser 옵션 시)
    │           ├─ 입력 필드 페이로드 인젝션 (8개 selector + 8 polyglot)
    │           ├─ MutationObserver: script/event handler 삽입 감지
    │           └─ URL 파라미터 Reflected XSS
    │
    ├─ Tech → Vuln Linking (핑거프린트 결과로 finding 설명 보강)
    ├─ Finding 중복 제거 (동일 URL 병합 + 크로스 URL Low/Info 집계)
    │
    └─ JSON 리포트 출력 (심각도 순 정렬)
```

### 3.3 동시성 모델

```
tokio::main (multi_thread)
    │
    ├─ Phase 1+2 병렬 ─── tokio::join!(port_scan, fingerprint)
    │
    ├─ Phase 4+5 병렬 ─── tokio::join!(analyzer.run(), engine.run_all())
    │   │
    │   ├─ analyzer: tokio::join!(SQLi, Traversal, CMDi, SSTI, CRLF, Redirect)
    │   │             join_all(파라미터별 SQLi/CMDi probe) — 베이스라인 기반 시간 검사
    │   │             join_all(폼 인젝션 병렬) — POST/GET 동시
    │   │             select_ok(5헤더 + 6경로변형 403 bypass)
    │   │             probe_common_params(14개 + SSTI 12개)
    │   │
    │   └─ engine:   spawn_blocking(Lua VM) × 28 스크립트
    │
    ├─ governor RateLimiter ─── 모든 HTTP 요청에 --rps 제한 적용
    │
    └─ Arc<Semaphore> (--threads 개수만큼 전체 동시 허용)
```

**결과 병합**: `Arc<Mutex<Vec<Finding>>>` 없이 각 Phase 결과를 순수 `Vec<Finding>`으로 반환 후 단순 `extend`로 병합한다.
병합 후 `dedup::deduplicate()`가 동일 URL 중복 제거 + 크로스 URL Low/Info 집계를 수행한다.

---

## 4. 탐지 항목 목록

### 4.1 자동 탐지 (내장)

| 카테고리 | 항목 | 심각도 |
|----------|------|--------|
| 기술 스택 | Apache, Nginx, IIS, WordPress, Drupal, Joomla, Laravel, Django, Spring, Express, PHP, ASP.NET, **Angular, React, Vue.js, Flask** | Info |
| 데이터베이스 | MySQL, PostgreSQL 에러 노출 | Info |
| CVE | 19개 시드 CVE 내장 + 기술 스택 버전 기반 semver 비교 | High |
| 포트 | 21/22/23/25/53/80/443/3306/3389/5432/6379/8080 등 29개 | Info |
| 보안 헤더 | X-Frame-Options, X-Content-Type-Options, HSTS (max-age 검증), CSP, Referrer-Policy, Permissions-Policy | Low |
| CORS | 와일드카드 오리진(*), 오리진 반사, Credentials 조합 | Medium~High |
| SQLi | 에러 기반 (14종 시그니처) + Time-based blind (베이스라인 + 4000ms), WAF evasion 적용 | High |
| Path Traversal | 16개 페이로드: basic, recursive-strip, double-encode, null-byte, UTF-8 overlong, absolute, Windows | High |
| Command Injection | echo-based 4종 + time-based 4종 (베이스라인 기반 임계값) | Critical |
| SSTI | 6개 엔진 (Jinja2/Twig, ERB, FreeMarker, Smarty, Mako, Thymeleaf) — 고유 수학식으로 오탐 방지 | Critical |
| CRLF Injection | `%0d%0a` 헤더 주입, 대소문자 무관 헤더 반영 확인 | High |
| 쿠키 | HttpOnly/Secure/SameSite 속성 누락 | Medium |
| 오픈 리디렉션 | Location 헤더 직접 검사 (no-follow), redirect/url/next/return/goto 등 7개 파라미터 | Medium |
| 재귀 크롤링 | BFS, 설정 가능 depth/max_urls, JS 엔드포인트 추출 (fetch/axios/XHR), **SPA JS 번들 파싱** | — |
| 공통 파라미터 프로빙 | param-less URL에 14개 공통 + 12개 SSTI 파라미터 추측 주입 | High~Critical |
| 폼 인젝션 | POST/GET 폼 필드 SQLi + CMDi 테스트 (join_all 병렬) | High~Critical |
| 본문 패턴 분석 | HTML 주석, hidden input, 내부 IP, 에러 트레이스 탐지 | Low~Medium |
| XSS (DOM) | `<script>`, `<img onerror>`, `<svg onload>` + 8개 polyglot + MutationObserver (8개 input selector) | High |
| XSS (Reflected) | URL 파라미터를 통한 JS 실행 확인 (basic + polyglot) | High |
| 403 Bypass | 5개 우회 헤더 + 6개 경로 변형 (대소문자, URL 인코딩, dot segment 등) | Medium |
| HTTP 메서드 | OPTIONS → TRACE/PUT/DELETE 허용 탐지 | Medium |
| 정보 유출 | 서버 버전, X-Powered-By, 디버그 헤더 6종 | Low |
| Mixed Content | HTTPS 페이지의 HTTP 리소스 로드 | Medium |
| WAF Evasion | 9개 인코딩 전략 (fast 3종 / --thorough 9종) | — |
| 레이트 리미팅 | governor 기반 초당 요청 수 제한 (--rps 플래그) | — |
| 인증 | Cookie/Bearer/Basic/Custom 헤더 (--cookie/--token/--basic-auth/--auth-header) | — |
| Finding 중복 제거 | 동일 URL 최고 심각도 유지 + 크로스 URL Low/Info 집계 + evidence 자르기 | — |
| Tech→Vuln 연결 | 핑거프린트 기술 스택 → 관련 취약점 설명에 컨텍스트 추가 | — |

### 4.2 Lua 스크립트 (플러그인)

총 28개 기본 제공:

| 스크립트 | 탐지 대상 | 심각도 |
|----------|-----------|--------|
| `example_custom_check.lua` | `.git/HEAD` 노출 | High |
| `env_file_check.lua` | `.env` 파일 자격증명 노출 | Critical |
| `ssrf_probe.lua` | 내부 IP / 클라우드 메타데이터 SSRF (15+ IP 인코딩 우회) | Critical |
| `ssti_probe.lua` | 템플릿 인젝션 10+ 엔진 (Jinja2 WAF 우회 포함) | Critical |
| `debug_endpoints.lua` | Actuator/Telescope/Werkzeug/Swagger 등 16개 | Critical |
| `wp_config_backup.lua` | WordPress 설정 백업 8개 경로 | Critical |
| `jwt_vulnerabilities.lua` | JWT none alg, 빈 시그니처, HS256 혼동, JWK/JKU/KID 인젝션 | Critical |
| `xxe_injection.lua` | XML 외부 엔티티, XInclude, Blind XXE, SOAP/WSDL | Critical |
| `deserialization.lua` | Java/PHP/Python/.NET/Node.js 역직렬화 탐지 | Critical |
| `nosql_injection.lua` | MongoDB 연산자 인젝션 ($ne/$gt/$regex), 인증 우회 | High |
| `file_upload_bypass.lua` | PHP 래퍼 (filter/expect/data/input), LFI, 업로드 폼 발견 | High |
| `idor_detection.lua` | 순차 ID 열거, IDOR 패턴 탐지 | High |
| `json_api_injection.lua` | REST API SQLi, type juggling, mass assignment | High |
| `prototype_pollution.lua` | 쿼리 파라미터 + JSON 본문 프로토타입 오염 | High |
| `graphql_introspection.lua` | GraphQL 스키마 인트로스펙션 | High |
| `cors_check.lua` | Origin 반사 CORS 테스트 | High |
| `host_header_injection.lua` | Host 헤더 주입 (비밀번호 초기화 중독) | High |
| `htaccess_exposure.lua` | `.htaccess`/`.htpasswd`/`web.config` 노출 | High |
| `backup_files.lua` | .zip/.sql/.tar 등 백업 파일 탐지 | High |
| `cve_js_libs.lua` | jQuery/Angular/Lodash/Bootstrap 취약 버전 | High |
| `admin_panels.lua` | 관리자/로그인 페이지 13개 경로 | Medium |
| `robots_sitemap.lua` | robots.txt 민감 경로 + sitemap.xml | Medium |
| `source_map.lua` | .js.map 소스맵 노출 | Medium |
| `info_disclosure.lua` | phpinfo/server-status/health 등 9개 | Medium |
| `error_page_leak.lua` | 에러 페이지 스택 트레이스/경로 유출 | Medium |
| `jsonp_callback.lua` | JSONP 콜백 엔드포인트 | Medium |

---

## 5. 기술 스택

| 구성 요소 | 크레이트 | 역할 |
|-----------|----------|------|
| 비동기 런타임 | `tokio 1` | 멀티스레드 async 실행, `join!`/`spawn_blocking` |
| CLI | `clap 4` | 인자 파싱, env 변수 연동 |
| HTTP 클라이언트 | `reqwest 0.12` | HTTP/2, TLS, 동적 커넥션 풀 |
| 헤드리스 브라우저 | `headless_chrome 1` | DevTools Protocol |
| Lua VM | `mlua 0.10` | LuaJIT 5.4, 샌드박스, `spawn_blocking` 병렬 |
| 상태 DB | `sled 0.34` | 임베디드 K-V 스토어 (스캔 상태 기록용, 향후 SQLite 통합 예정) |
| CVE DB | `rusqlite 0.31` | SQLite 번들 빌드 |
| 레이트 리미터 | `governor 0.8` | 초당 요청 수 제한 (--rps 플래그 연동) |
| 비동기 유틸 | `futures 0.3` | `join_all`, `select_ok` |
| 직렬화 | `serde + serde_json` | JSON 리포트 |
| 로깅 | `tracing + tracing-subscriber` | 구조화된 비동기 로그 |
| 에러 처리 | `anyhow + thiserror` | 에러 컨텍스트 체인 |
| 정규표현식 | `regex` | 핑거프린트 패턴 매칭 (OnceLock 캐시) |

---

## 6. 배포

### 6.1 로컬 빌드

```bash
# 개발 빌드
make build

# 릴리즈 최적화 빌드 (opt-level=3, lto, strip)
make release

# 시스템 설치 (/usr/local/bin/sentinel)
make install
```

### 6.2 Docker

```bash
# 이미지 빌드 (multi-stage: Rust builder → Debian+Chromium runtime)
make docker

# 실행
make docker-run ARGS="--target https://example.com --no-ports"

# docker compose 직접 사용
docker compose run sentinel --target https://example.com
```

### 6.3 GitHub Actions

| 워크플로 | 트리거 | 동작 |
|----------|--------|------|
| `ci.yml` | push/PR → main, develop | fmt → clippy → test → release 빌드 + artifact |
| `release.yml` | `v*` 태그 push | Linux AMD64 + macOS AMD64/ARM64 바이너리 빌드 → GitHub Release |

릴리즈 배포:
```bash
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions가 자동으로 멀티 플랫폼 바이너리 릴리즈 생성
```

---

## 7. 보안 설계

### 스코프 통제

```rust
// scope.rs: 승인된 도메인 외 URL은 자동 차단
pub fn is_in_scope(&self, url: &str) -> bool {
    host == self.allowed_host || host.ends_with(&format!(".{}", self.allowed_host))
}
```

### Lua 샌드박스

Lua 실행 환경에서 다음 모듈이 nil로 강제 설정된다.

```lua
io      → nil   -- 파일 시스템 접근 차단
os      → nil   -- 시스템 명령어 실행 차단
require → nil   -- 임의 모듈 로드 차단
package → nil
dofile  → nil
loadfile→ nil
debug   → nil   -- 내부 Lua 상태 접근 차단 (registry/hook 탈출 방지)
load    → nil   -- 런타임 코드 생성 차단 (문자열 → 바이트코드 변환 방지)
```

스크립트에서 허용된 API:
- `http.get(url)` — HTTP GET 요청
- `http.post(url, body)` — HTTP POST 요청 (form-urlencoded)
- `http.post_json(url, body)` — HTTP POST 요청 (application/json)
- `http.head(url)` — HTTP HEAD 요청 (바디 수신 생략)
- `http.get_with_headers(url, {key=val})` — 커스텀 헤더 GET 요청
- `report.finding(severity, category, title, description, url)` — 결과 보고
- 응답 필드: `status`, `body`, `headers`, `url` (최종 URL), `elapsed_ms` (응답 시간)

### Docker 최소 권한

- Non-root 사용자 `sentinel` (UID 1000)으로 실행
- 바이너리 + 설정 + 스크립트만 포함 (`target/`, `.git/` 제외)

### 레이트 리미팅

`--rps` 플래그로 초당 요청 수를 제한한다. 기본값 10 RPS.
`governor` 크레이트 기반으로 모든 HTTP 요청(GET/POST/HEAD/OPTIONS)에 대해 초당 요청 수를 강제한다.
Lua 스크립트의 요청도 동일한 rate limiter를 공유한다.

### 인증 지원

인증이 필요한 대상 스캔을 위해 4가지 방식을 지원한다.

```bash
# Cookie 인증 (세션 기반)
sentinel --target https://app.com --cookie "session=abc123; csrf=xyz"

# Bearer 토큰 (JWT/OAuth)
sentinel --target https://api.com --token "eyJhbGciOiJIUzI1NiIs..."

# Basic Auth
sentinel --target https://admin.com --basic-auth "admin:password"

# Custom 헤더 (API 키 등)
sentinel --target https://api.com --auth-header "X-API-Key:sk-12345"
```

인증 정보는 모든 HTTP 요청(내장 분석기 + Lua 스크립트)에 자동 적용된다.

---

## 8. 리포트 형식

스캔 결과는 JSON으로 출력된다.

```json
{
  "sentinel_version": "0.1.0",
  "target": "https://example.com",
  "scan_timestamp": "2026-03-20T10:30:00Z",
  "summary": {
    "total": 8,
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 2,
    "info": 1
  },
  "findings": [
    {
      "id": "f3a2b1c0-...",
      "severity": "high",
      "category": "xss",
      "title": "DOM-based XSS Detected",
      "description": "XSS confirmed via JS alert(). Payload: <svg onload=alert('XSS_SENTINEL')>",
      "url": "https://example.com/search",
      "evidence": "<svg onload=alert('XSS_SENTINEL')>",
      "cve": null,
      "remediation": "Sanitize output; use textContent not innerHTML; apply CSP.",
      "timestamp": "2026-03-20T10:31:42Z"
    }
  ]
}
```

### 심각도 기준

| 등급 | 기준 |
|------|------|
| Critical | 즉시 원격 코드 실행, 인증 없는 관리자 접근 |
| High | XSS, SQLi, CVE 매칭, .git/.env 노출 |
| Medium | 오픈 리디렉션, 쿠키 보안 속성 누락, 403 Bypass |
| Low | 보안 헤더 누락, HSTS 미설정 |
| Info | 기술 스택 탐지, 열린 포트 |

---

## 9. 한계 및 향후 계획

### 현재 한계

- robots.txt/sitemap.xml 기반 크롤 제어 미지원 (수동 스코프로 대체)
- NVD JSON 피드 자동 임포트 미구현 (수동 시드 19개 CVE)
- JSON POST body 기반 SQLi 탐지 미지원 (현재 URL 파라미터 + form 필드만)

### 구현 완료 항목

#### v0.1.0

| 항목 | 상태 |
|------|------|
| 재귀 크롤러 (멀티 레벨 링크 추적) | ✅ BFS depth/max_urls 설정 가능 |
| 인증 세션 지원 | ✅ `--cookie`, `--token`, `--basic-auth`, `--auth-header` |
| XXE 탐지 | ✅ `xxe_injection.lua` (XInclude, Blind XXE, SOAP/WSDL) |
| 레이트 리미팅 | ✅ governor 기반 `--rps` 강제 적용 |
| WAF 우회 | ✅ 9개 인코딩 전략, fast/thorough 2단계 |
| SSTI 탐지 | ✅ 6 엔진 내장 + Lua 스크립트 (10+ 엔진, WAF bypass) |
| Finding 중복 제거 | ✅ 동일 URL 병합 + 크로스 URL 집계 |
| JWT/NoSQL/IDOR 등 | ✅ 10개 신규 Lua 스크립트 추가 |

#### v0.1.1 (2026-03-24)

| 항목 | 상태 |
|------|------|
| SPA JS 엔드포인트 추출 | ✅ `<script src>` JS 파일 파싱 → API 경로 자동 발견 |
| SSTI 오탐 방지 | ✅ `913*773=705649` 고유값 + 베이스라인 체크 |
| SPA 백업 파일 오탐 제거 | ✅ SPA 감지 + Content-Type 검증 |
| htaccess 시그니처 정밀화 | ✅ 해시 패턴 기반 매칭 |
| Django 핑거프린트 오탐 수정 | ✅ body-only 시그니처 |
| 프레임워크 핑거프린트 확장 | ✅ Angular, React, Vue.js, Flask 추가 |
| prototype_pollution 버그 수정 | ✅ `os.clock()` → `math.random()` |

#### v0.1.2 (2026-03-25)

| 항목 | 분류 | 상태 |
|------|------|------|
| Lua 샌드박스 강화 — `debug`, `load` 차단 추가 | 보안 | ✅ `engine.rs` |
| CVE 버전 비교 오탐 수정 — `-debian` 등 suffix 처리 | 보안 | ✅ `cve.rs` |
| 크롤러 DFS → BFS 수정 (`VecDeque`) | 버그 | ✅ `crawler.rs` |
| `get_no_redirect` 클라이언트 재사용 (timeout/user_agent 일관성) | 버그 | ✅ `http.rs` |
| Regex `OnceLock` 캐싱 — `dedup.rs`, `evasion.rs` | 성능 | ✅ |
| 미사용 `config` 크레이트 제거 | 정리 | ✅ `Cargo.toml` |
| Finding 보강 로직 불변 변환 (`into_iter().map()`) | 코드 품질 | ✅ `orchestrator.rs` |

### 향후 로드맵

| 우선순위 | 항목 |
|----------|------|
| 높음 | JSON body SQLi 탐지 (REST API POST 요청) |
| 높음 | NVD JSON 피드 임포트 (`sentinel import-cve`) |
| 중간 | Null-byte path traversal 탐지 (`%2500` 우회) |
| 중간 | robots.txt 준수 크롤링 |
| 중간 | HTML 리포트 출력 |
| 낮음 | ARM64 Linux 공식 빌드 지원 |
| 낮음 | WebSocket 취약점 탐지 |

---

## 10. 결론

Sentinel은 CERT 진단 업무의 자동화 효율을 높이기 위해 설계된 도구다.

기존 도구 대비 세 가지 차별점이 있다.

1. **정밀도**: 헤드리스 브라우저로 XSS를 실제 JS 실행으로 검증 (False Positive 없음)
2. **확장성**: Lua 플러그인으로 재컴파일 없이 새 진단 로직 추가 가능
3. **경량성**: 단일 바이너리 14MB, 외부 서버 불필요, Docker 이미지로 즉시 배포 가능

진단 인력은 `sentinel --target <URL>`만으로 포트 스캔부터 XSS 검증까지 전 과정을 자동 실행할 수 있으며,
Lua 스크립트를 추가해 조직 특화 진단 규칙을 즉시 적용할 수 있다.
팀 환경에서는 Docker 이미지 또는 GitHub Actions 릴리즈 바이너리를 통해 버전 관리와 배포를 표준화할 수 있다.
