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
    ├─ SQLi (에러 기반 14종 + Time-based blind) → join_all 파라미터별
    ├─ Path Traversal → 5개 페이로드, 5개 OS 시그니처
    ├─ Command Injection → echo-based + time-based (elapsed_ms ≥ 4.5s)
    ├─ CRLF Injection → 헤더 주입 확인
    └─ Open Redirect → 리디렉션 파라미터 7종

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
│   ├── main.rs              # CLI 진입점 (clap)
│   ├── core/
│   │   ├── scanner.rs       # ScanConfig, ScanContext, Finding 타입 정의
│   │   └── orchestrator.rs  # 6개 Phase 조율 (Phase 1+2, 4+5 병렬)
│   ├── network/
│   │   ├── http.rs          # reqwest 래퍼 (재시도, 동적 커넥션 풀)
│   │   ├── port.rs          # 비동기 TCP 포트 스캐너
│   │   ├── fingerprint.rs   # Wappalyzer 스타일 기술 스택 탐지 (OnceLock 패턴 캐시)
│   │   ├── analyzer.rs      # 응답 분석 + 피드백 루프
│   │   └── scope.rs         # 스코프 가드 (out-of-scope URL 차단)
│   ├── db/
│   │   ├── cve.rs           # CVE SQLite DB (검색, 삽입)
│   │   └── state.rs         # sled 기반 스캔 상태 영속화
│   ├── scripting/
│   │   └── engine.rs        # Lua VM (mlua), 샌드박스, spawn_blocking 병렬 실행
│   ├── browser/
│   │   ├── controller.rs    # Chrome 실행/탭 관리
│   │   └── xss.rs           # DOM XSS 인젝션 + alert() 감지
│   └── report/
│       └── json.rs          # JSON 리포트 직렬화
├── scripts/                 # 사용자 Lua 플러그인 디렉터리
├── Dockerfile               # Multi-stage 빌드 (builder → runtime+Chromium)
├── docker-compose.yml       # 로컬 실행 + Juice Shop 테스트 프로파일
├── .dockerignore
├── Makefile                 # build / release / test / lint / install / docker
├── sentinel.toml            # 기본 설정 파일
└── docs/                   # 이 문서들
```

### 3.2 스캔 실행 흐름

```
CLI 파싱 (clap)
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
    ├─ [병렬] Phase 4 + Phase 5  ← tokio::join!
    │   ├─ Phase 4: HTTP 취약점 점검
    │   │   ├─ [패시브] 보안 헤더 6종 / CORS / 쿠키 / Mixed Content / 정보 유출
    │   │   ├─ [능동, 병렬] SQLi (에러+Blind) / Path Traversal / CMDi / CRLF / Open Redirect
    │   │   ├─ HTTP Method 검사 (OPTIONS)
    │   │   └─ 403 Bypass (5개 헤더 + 6개 경로 변형, select_ok 경쟁)
    │   └─ Phase 5: Lua 스크립트 실행
    │               (scripts/*.lua 파일 → spawn_blocking 병렬)
    │
    ├─ Phase 6: 헤드리스 브라우저 XSS 탐지 (--browser 옵션 시)
    │           ├─ 입력 필드 페이로드 인젝션
    │           └─ URL 파라미터 Reflected XSS
    │
    └─ JSON 리포트 출력
```

### 3.3 동시성 모델

```
tokio::main (multi_thread)
    │
    ├─ Phase 1+2 병렬 ─── tokio::join!(port_scan, fingerprint)
    │
    ├─ Phase 4+5 병렬 ─── tokio::join!(analyzer.run(), engine.run_all())
    │   │
    │   ├─ analyzer: tokio::join!(SQLi, Traversal, CMDi, CRLF, Redirect)
    │   │             select_ok(5헤더 + 6경로변형 403 bypass)
    │   │
    │   └─ engine:   spawn_blocking(Lua VM) × N 스크립트
    │
    └─ Arc<Semaphore> (--threads 개수만큼 전체 동시 허용)
```

**결과 병합**: `Arc<Mutex<Vec<Finding>>>` 없이 각 Phase 결과를 순수 `Vec<Finding>`으로 반환 후 단순 `extend`로 병합한다.

---

## 4. 탐지 항목 목록

### 4.1 자동 탐지 (내장)

| 카테고리 | 항목 | 심각도 |
|----------|------|--------|
| 기술 스택 | Apache, Nginx, IIS, WordPress, Drupal, Joomla, Laravel, Django, Spring, Express, PHP, ASP.NET | Info |
| 데이터베이스 | MySQL, PostgreSQL 에러 노출 | Info |
| CVE | 탐지된 기술 스택 버전 기반 CVE 매칭 | High |
| 포트 | 21/22/23/25/53/80/443/3306/3389/5432/6379/8080 등 29개 | Info |
| 보안 헤더 | X-Frame-Options, X-Content-Type-Options, HSTS (max-age 검증), CSP, Referrer-Policy, Permissions-Policy | Low |
| CORS | 와일드카드 오리진(*), 오리진 반사, Credentials 조합 | Medium~High |
| SQLi | 에러 기반 (14종 시그니처) + Time-based blind (SLEEP/pg_sleep/WAITFOR) | High |
| Path Traversal | `../../etc/passwd` 등 5개 페이로드, 5개 OS 시그니처 | High |
| Command Injection | echo-based 4종 + time-based 4종 (elapsed_ms ≥ 4.5s) | Critical |
| CRLF Injection | `%0d%0a` 헤더 주입, 응답 헤더 반영 확인 | High |
| 쿠키 | HttpOnly/Secure/SameSite 속성 누락 | Medium |
| 오픈 리디렉션 | redirect/url/next/return/goto 등 7개 파라미터 | Medium |
| XSS (DOM) | `<script>`, `<img onerror>`, `<svg onload>` 등 | High |
| XSS (Reflected) | URL 파라미터를 통한 JS 실행 확인 | High |
| 403 Bypass | 5개 우회 헤더 + 6개 경로 변형 (대소문자, URL 인코딩, dot segment 등) | Medium |
| HTTP 메서드 | OPTIONS → TRACE/PUT/DELETE 허용 탐지 | Medium |
| 정보 유출 | 서버 버전, X-Powered-By, 디버그 헤더 6종 | Low |
| Mixed Content | HTTPS 페이지의 HTTP 리소스 로드 | Medium |

### 4.2 Lua 스크립트 (플러그인)

총 18개 기본 제공:

| 스크립트 | 탐지 대상 | 심각도 |
|----------|-----------|--------|
| `example_custom_check.lua` | `.git/HEAD` 노출 | High |
| `env_file_check.lua` | `.env` 파일 자격증명 노출 | Critical |
| `ssrf_probe.lua` | 내부 IP / 클라우드 메타데이터 SSRF | Critical |
| `ssti_probe.lua` | 템플릿 인젝션 (Jinja2/FreeMarker/ERB 등) | Critical |
| `debug_endpoints.lua` | Actuator/Telescope/Werkzeug/Swagger 등 16개 | Critical |
| `wp_config_backup.lua` | WordPress 설정 백업 8개 경로 | Critical |
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
| 상태 DB | `sled 0.34` | 임베디드 K-V 스토어 |
| CVE DB | `rusqlite 0.31` | SQLite 번들 빌드 |
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
```

스크립트에서 허용된 API:
- `http.get(url)` — HTTP GET 요청
- `http.post(url, body)` — HTTP POST 요청
- `http.head(url)` — HTTP HEAD 요청 (바디 수신 생략)
- `http.get_with_headers(url, {key=val})` — 커스텀 헤더 GET 요청
- `report.finding(severity, category, title, description, url)` — 결과 보고
- 응답 필드: `status`, `body`, `headers`, `url` (최종 URL), `elapsed_ms` (응답 시간)

### Docker 최소 권한

- Non-root 사용자 `sentinel` (UID 1000)으로 실행
- 바이너리 + 설정 + 스크립트만 포함 (`target/`, `.git/` 제외)

### 레이트 리미팅

`--rps` 플래그로 초당 요청 수를 제한한다. 기본값 10 RPS.

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

- CVE DB가 비어 있음 — NVD/MITRE 데이터 임포트 스크립트 미구현
- 인증 세션 처리 없음 (로그인 후 스캔 불가)
- 크롤링 미구현 (단일 URL만 분석, 링크 추적 없음)
- XXE 탐지 플러그인 미제공 (Lua로 확장 가능)

### 향후 로드맵

| 우선순위 | 항목 |
|----------|------|
| 높음 | NVD JSON 피드 임포트 (`sentinel import-cve`) |
| 높음 | 재귀 크롤러 (robots.txt 준수) |
| 중간 | 인증 세션 지원 (`--cookie`, `--auth-header`) |
| 중간 | XXE Lua 플러그인 추가 |
| 낮음 | HTML 리포트 출력 |
| 낮음 | ARM64 Linux 공식 빌드 지원 |

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
