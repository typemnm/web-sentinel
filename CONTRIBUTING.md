# Contributing to Sentinel

Sentinel에 기여해 주셔서 감사합니다. 이 문서는 프로젝트에 기여하는 방법을 설명합니다.

---

## 기여 방식

| 방식 | 난이도 | 필요 지식 | 설명 |
|------|--------|-----------|------|
| **Lua 스크립트** | 낮음 | Lua + HTTP 기초 | 새로운 취약점 탐지 플러그인 작성 |
| **버그 리포트** | 낮음 | - | Issue로 오탐/미탐/충돌 보고 |
| **문서 개선** | 낮음 | - | 오타 수정, 사용 예시 추가 |
| **Rust 엔진** | 높음 | Rust + tokio + 보안 | 코어 분석 엔진 개선 |

**Lua 스크립트 기여가 가장 쉽고 효과가 큽니다.** Rust를 몰라도 HTTP와 보안 지식만 있으면 바로 기여할 수 있습니다.

---

## Lua 스크립트 기여 가이드

### 1단계: 환경 준비

```bash
# Fork 후 클론
git clone https://github.com/<your-username>/web-sentinel
cd web-sentinel

# 빌드 확인
make build
make test
```

### 2단계: 스크립트 작성

`scripts/` 디렉터리에 `.lua` 파일을 생성합니다.

#### 파일 이름 규칙

```
<탐지_대상>_<검사_유형>.lua
```

예시:
- `xml_xxe.lua` — XXE 인젝션 탐지
- `firebase_misconfig.lua` — Firebase 설정 오류 탐지
- `api_key_leak.lua` — 응답 본문에서 API 키 노출 탐지

**금지**: 공백, 대문자, 하이픈 사용 (`my-check.lua` → `my_check.lua`)

#### 스크립트 템플릿

```lua
-- [한 줄 설명: 이 스크립트가 무엇을 탐지하는지]

-- 1. 검사 대상 정의
local checks = {
    {path = "/target-path", sig = "signature", name = "Human-readable Name"},
}

-- 2. 검사 실행
for _, c in ipairs(checks) do
    local resp = http.get(TARGET .. c.path)

    -- 3. 응답 검증 (상태코드 + 시그니처)
    if resp.status == 200 and resp.body:lower():find(c.sig:lower()) then
        report.finding(
            "medium",           -- severity: critical / high / medium / low / info
            "custom",           -- category: xss / sqli / ssrf / traversal / cmdi / crlf / cors / custom
            "Finding Title: " .. c.name,
            "Description of what was found and why it matters.",
            TARGET .. c.path
        )
    end
end
```

### 3단계: 로컬 테스트

```bash
# 스캔 실행으로 스크립트 동작 확인
make scan TARGET=http://localhost:8080

# 상세 로그로 스크립트 오류 확인
sentinel --target http://localhost:8080 -vv 2>&1 | grep -i "script\|lua\|error"

# OWASP Juice Shop으로 테스트 (권장)
docker compose --profile test up -d
sentinel --target http://localhost:3000 --no-ports -vv
```

### 4단계: PR 제출

```bash
git checkout -b feat/add-xxe-probe
git add scripts/xml_xxe.lua
git commit -m "feat(scripts): add XXE injection probe"
git push origin feat/add-xxe-probe
```

GitHub에서 Pull Request를 생성합니다.

---

## 스크립트 작성 가이드라인

### 필수 사항

| 항목 | 설명 |
|------|------|
| **첫 줄 주석** | `-- 한 줄 설명` 으로 시작 (파일 목적 명시) |
| **시그니처 검증** | 상태 코드만이 아닌, 응답 본문/헤더에서 시그니처 확인 필수 |
| **정확한 심각도** | 아래 심각도 기준표 준수 |
| **명확한 제목** | Finding 제목만으로 무엇이 발견되었는지 알 수 있어야 함 |
| **URL 포함** | `report.finding()`의 마지막 인자에 취약한 URL 포함 |

### 금지 사항

| 항목 | 이유 |
|------|------|
| `io.*`, `os.*`, `require()` 사용 | 샌드박스에서 차단됨 (nil) |
| 무한 루프, 재귀 | 스캔 전체를 블로킹 |
| 100개 이상 경로 브루트포스 | 과도한 요청은 DoS와 같음 |
| 하드코딩된 외부 URL 접속 | 스캔 대상 외 호스트 요청 금지 |
| 인증 정보 하드코딩 | 절대 금지 |

### 심각도 기준

| 등급 | 기준 | 예시 |
|------|------|------|
| `critical` | 인증 없는 원격 코드 실행, 전체 데이터 유출 | SSRF → 클라우드 메타데이터, 디버거 콘솔 노출 |
| `high` | 데이터 유출, 계정 탈취 가능 | XSS, SQLi, .git 노출, 취약한 JS 라이브러리 |
| `medium` | 제한된 정보 유출, 보안 우회 | 관리자 페이지 노출, JSONP, 소스맵 노출 |
| `low` | 보안 모범 사례 미준수 | 보안 헤더 누락, 정보성 엔드포인트 |
| `info` | 참고 정보 | 기술 스택 탐지, 열린 포트 |

### 오탐(False Positive) 최소화 원칙

**가장 중요한 원칙입니다.** 스캐너의 가치는 정밀도에 달려 있습니다.

```lua
-- BAD: 상태코드만으로 판단 → 오탐 발생
if resp.status == 200 then
    report.finding(...)
end

-- GOOD: 상태코드 + 본문 시그니처 이중 확인
if resp.status == 200 and resp.body:find("phpMyAdmin") then
    report.finding(...)
end

-- BETTER: 여러 시그니처 중 하나 이상 일치
if resp.status == 200 and (
    resp.body:find("phpMyAdmin") or
    resp.body:find("pma_navigation")
) then
    report.finding(...)
end
```

### 요청 수 최소화 원칙

```lua
-- BAD: 수백 개 경로를 모두 GET으로 확인
for _, path in ipairs(huge_path_list) do
    local resp = http.get(TARGET .. path)
end

-- GOOD: HEAD로 존재 여부만 먼저 확인, 존재하면 GET
for _, path in ipairs(paths) do
    local head = http.head(TARGET .. path)
    if head.status == 200 then
        local resp = http.get(TARGET .. path)
        -- 시그니처 검증 후 리포트
    end
end
```

### 응답 시간 활용 (Time-based 탐지)

```lua
-- elapsed_ms로 시간 기반 탐지 가능
local resp = http.get(TARGET .. "/api?id=1' AND SLEEP(5)--")
if resp.elapsed_ms >= 4500 then
    report.finding("high", "sqli",
        "Time-based Blind SQLi",
        "Response delayed by " .. resp.elapsed_ms .. "ms after SLEEP injection.",
        TARGET .. "/api?id=..."
    )
end
```

---

## 사용 가능한 Lua API

| 함수 | 설명 | 반환 |
|------|------|------|
| `http.get(url)` | GET 요청 | 응답 테이블 |
| `http.post(url, body)` | POST 요청 (form-urlencoded) | 응답 테이블 |
| `http.post_json(url, body)` | POST 요청 (application/json) | 응답 테이블 |
| `http.head(url)` | HEAD 요청 (바디 없음) | 응답 테이블 |
| `http.get_with_headers(url, {k=v})` | 커스텀 헤더 GET | 응답 테이블 |
| `report.finding(sev, cat, title, desc, url)` | 취약점 보고 | - |
| `TARGET` | 스캔 대상 URL (전역 변수) | string |

**응답 테이블 필드:**

| 필드 | 타입 | 설명 |
|------|------|------|
| `status` | number | HTTP 상태 코드 |
| `body` | string | 응답 본문 (`head`는 빈 문자열) |
| `headers` | table | 헤더 (키 소문자) |
| `url` | string | 리디렉션 후 최종 URL |
| `elapsed_ms` | number | 요청~응답 시간 (ms) |

---

## 필요한 스크립트 (Wishlist)

아래 영역의 스크립트 기여를 환영합니다.

| 스크립트 | 설명 | 난이도 |
|----------|------|--------|
| `firebase_misconfig.lua` | Firebase Realtime DB `.json` 접근 | 낮음 |
| `s3_bucket_enum.lua` | S3 버킷 공개 접근 탐지 | 낮음 |
| `api_key_leak.lua` | 응답에서 API 키/토큰 패턴 탐지 | 낮음 |
| `websocket_check.lua` | WebSocket 인증 없는 접근 | 중간 |
| `cache_poisoning.lua` | 웹 캐시 포이즈닝 탐지 | 높음 |
| `subdomain_takeover.lua` | CNAME 댕글링 탐지 | 높음 |
| `open_redirect_advanced.lua` | 고급 오픈 리디렉트 (인코딩 우회) | 중간 |

> **이미 내장된 스크립트 (28개)**: JWT 취약점, XXE 인젝션, 프로토타입 폴루션, NoSQL 인젝션, SSRF, SSTI, IDOR, 역직렬화, 파일 업로드 우회, GraphQL 인트로스펙션, 디버그 엔드포인트, WordPress 설정 백업, robots.txt, 백업 파일, 관리자 패널, 소스맵, CORS 리플렉션, Host 헤더 인젝션, .htaccess/.htpasswd, 정보 유출, 에러 페이지, JSONP 콜백, 취약한 JS 라이브러리, .git 노출, .env 노출 등.
>
> Issue에 `script-idea` 라벨로 새 아이디어를 제안할 수도 있습니다.

---

## 기존 스크립트 참고

새 스크립트를 작성할 때 기존 스크립트를 참고하세요.

| 패턴 | 참고 스크립트 | 핵심 기법 |
|------|---------------|-----------|
| 경로 목록 순회 | `admin_panels.lua`, `debug_endpoints.lua` | 경로 + 시그니처 테이블 |
| HEAD로 빠른 확인 | `backup_files.lua` | `http.head()` → 존재 확인 |
| 파라미터 인젝션 | `ssrf_probe.lua` | URL 쿼리 파라미터 치환 |
| 커스텀 헤더 | `cors_check.lua`, `host_header_injection.lua` | `http.get_with_headers()` |
| 응답 시간 분석 | `ssti_probe.lua` | `resp.elapsed_ms` 활용 |
| 버전 비교 | `cve_js_libs.lua` | 정규식 버전 추출 + 비교 |
| 본문 파싱 | `robots_sitemap.lua`, `source_map.lua` | 응답 본문에서 경로 추출 → 추가 요청 |

---

## 커밋 메시지 컨벤션

```
<type>(<scope>): <description>

# 예시
feat(scripts): add XXE injection probe
fix(scripts): reduce false positives in admin_panels.lua
docs: update Lua API examples in CONTRIBUTING.md
feat(engine): add http.options() to Lua sandbox
fix(analyzer): correct time-based SQLi threshold
```

| Type | 용도 |
|------|------|
| `feat` | 새 기능 (스크립트, 엔진 기능) |
| `fix` | 버그 수정, 오탐 수정 |
| `docs` | 문서만 변경 |
| `refactor` | 기능 변경 없는 구조 개선 |
| `test` | 테스트 추가/수정 |

---

## PR 체크리스트

PR을 제출하기 전에 아래 항목을 확인하세요.

### Lua 스크립트 PR

- [ ] 첫 줄에 `-- 한 줄 설명` 주석이 있다
- [ ] 파일명이 `snake_case.lua` 형식이다
- [ ] `report.finding()`에 5개 인자를 모두 전달한다 (severity, category, title, description, url)
- [ ] 상태 코드 + 시그니처로 이중 검증한다 (오탐 방지)
- [ ] 요청 수가 적절하다 (경로 50개 이내, 불필요한 GET 대신 HEAD 사용)
- [ ] `io`, `os`, `require` 등 차단된 API를 사용하지 않는다
- [ ] TARGET 외 호스트에 요청하지 않는다
- [ ] 로컬 테스트를 완료했다 (`-vv`로 오류 없음 확인)
- [ ] 기존 스크립트와 기능이 중복되지 않는다

### Rust 코드 PR

- [ ] `make check` 통과 (fmt + clippy + test)
- [ ] 새 기능에 대한 단위 테스트 추가
- [ ] 기존 테스트 깨지지 않음
- [ ] `unsafe` 코드 사용하지 않음

---

## Rust 엔진 기여

Rust 코어 엔진에 기여하려면 아래 구조를 이해해야 합니다.

```
src/
├── core/
│   ├── scanner.rs        # Finding, FindingCategory, ScanConfig 타입 정의
│   └── orchestrator.rs   # 6-phase 스캔 파이프라인 + Finding 중복 제거 + 기술→취약점 연계
├── network/
│   ├── http.rs           # HttpClient (governor 레이트리미터, 인증, elapsed_ms)
│   ├── analyzer.rs       # 취약점 분석 (패시브 → 능동 → 스페셜, 베이스라인 기반)
│   ├── crawler.rs        # 재귀 크롤러 (BFS + JS 엔드포인트 추출)
│   ├── evasion.rs        # WAF 우회 전략 (fast 3종 / thorough 9종)
│   └── ...
├── report/
│   └── dedup.rs          # Finding 중복 제거 + 크로스 URL 집계
├── browser/
│   └── xss.rs            # 헤드리스 Chrome XSS (MutationObserver + 폴리글롯)
└── scripting/engine.rs   # Lua VM, 샌드박스, http/report API 바인딩
```

**새 Lua API 추가 시:**
1. `http.rs`에 새 메서드 구현
2. `engine.rs`의 `resp_to_lua_table()`로 응답 변환
3. `engine.rs`에 Lua 바인딩 등록
4. `CONTRIBUTING.md` 및 `docs/user-guide.md`의 API 테이블 업데이트

**새 FindingCategory 추가 시:**
1. `scanner.rs`의 `FindingCategory` enum에 추가
2. `engine.rs`의 카테고리 매핑에 문자열 추가
3. 문서 업데이트

---

## Issue 보고

### 오탐(False Positive) 보고

```markdown
**스크립트**: admin_panels.lua
**대상 URL**: https://example.com
**리포트된 Finding**: Exposed Admin Panel at /admin
**실제 상태**: /admin은 정적 마케팅 페이지이며 관리자 패널이 아님
**제안**: 시그니처에 login form 존재 여부를 추가 검증
```

### 미탐(False Negative) 보고

```markdown
**기대한 탐지**: WordPress 설정 파일 노출
**대상 URL**: https://example.com/wp-config.php.bak
**실제 결과**: 탐지되지 않음
**원인 추정**: wp_config_backup.lua의 경로 목록에 .php.bak 확장자 누락
```

---

## 라이선스

기여하신 코드는 프로젝트와 동일한 [MIT 라이선스](LICENSE)로 배포됩니다.
PR을 제출함으로써 이에 동의하는 것으로 간주합니다.

---

## 질문이 있다면

- [GitHub Issues](https://github.com/typemnm/web-sentinel/issues)에 `question` 라벨로 질문을 남겨주세요.
- 스크립트 아이디어는 `script-idea` 라벨을 사용하세요.
