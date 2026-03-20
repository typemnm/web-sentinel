# Sentinel 사용자 가이드

> 이 문서는 Sentinel을 설치하고 실제 진단에 사용하는 방법을 설명한다.

---

## 1. 설치

### 사전 요구사항

| 구성 | 버전 | 비고 |
|------|------|------|
| Rust | 1.75+ | `rustup` 권장 |
| Google Chrome / Chromium | 최신 | `--browser` 옵션 사용 시만 필요 |
| Linux (x86_64) / macOS | WSL2 포함 | Docker 사용 시 OS 무관 |

### 방법 A: 바이너리 직접 설치 (권장)

GitHub Releases 페이지에서 플랫폼에 맞는 바이너리를 다운로드한다.

```bash
# Linux AMD64
curl -LO https://github.com/typemnm/web-sentinel/releases/latest/download/sentinel-linux-amd64.tar.gz
tar xzf sentinel-linux-amd64.tar.gz
sudo mv sentinel /usr/local/bin/

# macOS ARM64 (Apple Silicon)
curl -LO https://github.com/typemnm/web-sentinel/releases/latest/download/sentinel-macos-arm64.tar.gz
tar xzf sentinel-macos-arm64.tar.gz
sudo mv sentinel /usr/local/bin/
```

### 방법 B: 소스 빌드

```bash
git clone <repo-url> sentinel
cd sentinel

# Makefile 사용 (권장)
make release          # target/release/sentinel 생성
make install          # /usr/local/bin/sentinel 에 설치

# 또는 직접 cargo 사용
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
```

### 방법 C: Docker

```bash
# 이미지 빌드
make docker
# 또는
docker build -t sentinel:latest .

# 실행 (결과는 ./output/ 에 저장)
docker run --rm \
    -v "$(pwd)/output:/app/output" \
    -v "$(pwd)/scripts:/app/scripts" \
    sentinel:latest --target https://example.com
```

### Chromium 설치 (브라우저 스캔 시만 필요)

```bash
# Ubuntu / Debian
sudo apt-get install chromium-browser

# Arch
sudo pacman -S chromium

# Docker 사용 시 이미지에 포함되어 있어 별도 설치 불필요
```

---

## 2. 빠른 시작

### 기본 스캔

```bash
sentinel --target http://example.com
```

이것만으로 아래가 자동 실행된다.
- 공통 포트 29개 스캔
- 기술 스택 핑거프린팅 (14+ 패턴)
- CVE 상관관계 분석
- HTTP 취약점 점검
  - 보안 헤더 6종, CORS, 쿠키 보안, Mixed Content, 정보 유출 (패시브)
  - SQLi (에러 기반 + Time-based blind), Path Traversal, Command Injection, CRLF Injection, Open Redirect (능동, 병렬)
  - HTTP 메서드 검사, 403 Bypass (11개 기법)
- `scripts/` 디렉터리의 Lua 플러그인 18개 병렬 실행

결과는 `sentinel_report.json`에 저장된다.

### 브라우저 포함 전체 스캔 (XSS 포함)

```bash
sentinel --target http://example.com --browser
```

### 조용한 모드 (CI/CD 적합)

```bash
sentinel --target http://example.com --silent -o /tmp/result.json
```

### Makefile 단축 명령

```bash
make scan TARGET=https://example.com   # 빌드 후 바로 스캔
make test                              # 전체 테스트 실행
make check                             # fmt + clippy + test 한번에
```

---

## 3. CLI 옵션 전체 참조

```
Usage: sentinel [OPTIONS]

Options:
  -t, --target <TARGET>         스캔 대상 도메인 또는 URL
  -o, --output <OUTPUT>         JSON 리포트 저장 경로 [기본: sentinel_report.json]
      --threads <N>             동시 작업 수 [기본: 50]
      --rps <N>                 초당 최대 요청 수 [기본: 10]
  -s, --silent                  경고 이상만 출력
  -v, --verbose                 상세 로그 (-v: debug, -vv: trace)
      --scripts-dir <DIR>       Lua 스크립트 디렉터리 [기본: scripts]
      --config <FILE>           설정 파일 경로 [기본: sentinel.toml]
      --browser                 헤드리스 브라우저 스캔 활성화
      --no-ports                포트 스캔 생략
      --scope <DOMAIN>          허용 스코프 도메인 (기본: --target에서 자동 추출)
      --timeout <SEC>           요청 타임아웃 (초) [기본: 10]
      --user-agent <UA>         User-Agent 오버라이드
  -h, --help                    도움말 출력
  -V, --version                 버전 출력
```

### 환경변수로 설정

모든 주요 옵션은 환경변수로도 지정할 수 있다.

| 환경변수 | 해당 옵션 |
|----------|-----------|
| `SENTINEL_TARGET` | `--target` |
| `SENTINEL_OUTPUT` | `--output` |
| `SENTINEL_THREADS` | `--threads` |
| `SENTINEL_RPS` | `--rps` |
| `SENTINEL_SCRIPTS` | `--scripts-dir` |
| `SENTINEL_CONFIG` | `--config` |

```bash
export SENTINEL_TARGET=http://testsite.local
export SENTINEL_RPS=5
sentinel
```

---

## 4. 설정 파일 (sentinel.toml)

프로젝트 루트의 `sentinel.toml`로 기본값을 조정할 수 있다.

```toml
[scan]
threads = 50        # 동시 작업 수
rps = 10            # 초당 요청 수
timeout = 10        # 요청 타임아웃 (초)
browser = false     # 헤드리스 브라우저 기본 비활성
port_scan = true    # 포트 스캔 기본 활성

[output]
file = "sentinel_report.json"
format = "json"

[http]
user_agent = "Mozilla/5.0 (compatible; Sentinel/0.1.0)"
follow_redirects = true
max_redirects = 5

[scripts]
dir = "scripts"
```

CLI 인자가 항상 설정 파일보다 우선한다.

---

## 5. 사용 시나리오

### 시나리오 1: 빠른 HTTP 전용 점검 (포트 생략)

```bash
sentinel \
  --target https://target.example.com \
  --no-ports \
  --rps 20 \
  --threads 100 \
  -o report_quick.json
```

### 시나리오 2: 전체 심층 진단 (브라우저 포함)

```bash
sentinel \
  --target http://internal-app.local \
  --browser \
  --threads 30 \
  --rps 5 \
  --timeout 15 \
  -vv \
  -o report_deep.json
```

### 시나리오 3: 스코프 제한 (서브도메인 포함)

```bash
sentinel \
  --target https://app.example.com \
  --scope example.com \
  -o report.json
```

`--scope example.com`으로 설정하면 `*.example.com` 전체가 허용된다.
기본적으로 `--target`의 호스트가 자동으로 스코프로 설정된다.

### 시나리오 4: GitHub Actions CI/CD 파이프라인

`.github/workflows/ci.yml`이 이미 설정되어 있어, `main` 브랜치 push/PR 시 자동으로 스캔 테스트가 실행된다.
수동 진단 파이프라인에 연동할 경우:

```yaml
# .github/workflows/security-scan.yml 예시
- name: Run Sentinel
  run: |
    sentinel \
      --target ${{ env.DEPLOY_URL }} \
      --silent \
      --no-ports \
      -o /tmp/sentinel.json

- name: Check for critical findings
  run: |
    python3 -c "
    import json, sys
    r = json.load(open('/tmp/sentinel.json'))
    high = r['summary']['high'] + r['summary']['critical']
    if high > 0:
        print(f'FAIL: {high} High/Critical findings')
        sys.exit(1)
    print('PASS')
    "
```

### 시나리오 5: Docker로 격리 실행

```bash
# 기본 스캔
docker compose run sentinel --target https://example.com

# 결과 파일 확인
ls -la output/

# Juice Shop 로컬 인스턴스에 대한 테스트
docker compose --profile test up -d
docker compose run sentinel --target http://juice-shop:3000 --no-ports
```

### 시나리오 6: 커스텀 User-Agent

```bash
sentinel \
  --target http://target.local \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
```

---

## 6. Lua 플러그인 작성 가이드

### 기본 구조

`scripts/` 디렉터리에 `.lua` 파일을 만들면 자동으로 실행된다.
스크립트는 독립적인 `spawn_blocking` 스레드에서 병렬 실행된다.

```lua
-- scripts/my_check.lua

-- TARGET: 현재 스캔 대상 URL (자동 주입)
local resp = http.get(TARGET .. "/admin")

if resp.status == 200 then
    report.finding(
        "high",              -- 심각도: critical / high / medium / low / info
        "custom",            -- 카테고리: xss / sqli / ssrf / traversal / cmdi / crlf / cors / custom
        "Exposed Admin Page",-- 제목
        "Admin page is accessible without authentication.",  -- 설명
        TARGET .. "/admin"   -- 취약한 URL
    )
end
```

### 사용 가능한 API

#### `http.get(url)`

HTTP GET 요청을 수행하고 응답 테이블을 반환한다.

```lua
local resp = http.get("http://example.com/api/data")

-- resp.status   : number  (HTTP 상태 코드)
-- resp.body     : string  (응답 본문)
-- resp.headers  : table   (헤더 키-값, 소문자)

print(resp.status)                    -- 200
print(resp.body)                      -- "{"key":"val"}"
print(resp.headers["content-type"])   -- "application/json"
```

#### `http.post(url, body)`

HTTP POST 요청을 수행한다 (Content-Type: application/x-www-form-urlencoded).

```lua
local resp = http.post(TARGET .. "/login", "username=admin&password=admin")
print(resp.status)       -- 200 or 302
print(resp.elapsed_ms)   -- 응답 시간 (ms)
```

#### `http.head(url)`

HTTP HEAD 요청 — 바디를 수신하지 않아 빠른 존재 확인에 적합하다.

```lua
local resp = http.head(TARGET .. "/backup.zip")
if resp.status == 200 then
    -- 파일 존재 확인
end
```

#### `http.get_with_headers(url, headers)`

커스텀 헤더를 포함한 GET 요청. CORS, Host 헤더 인젝션 테스트에 사용.

```lua
local resp = http.get_with_headers(TARGET, {
    ["Origin"] = "https://evil.com",
    ["Host"] = "evil.com"
})
print(resp.headers["access-control-allow-origin"])
```

#### 응답 공통 필드

모든 `http.*` 함수의 응답 테이블은 아래 필드를 포함한다.

```lua
resp.status       -- number  (HTTP 상태 코드)
resp.body         -- string  (응답 본문, head는 빈 문자열)
resp.headers      -- table   (헤더 키-값, 소문자)
resp.url          -- string  (리디렉션 후 최종 URL)
resp.elapsed_ms   -- number  (요청~응답 시간, 밀리초)
```

#### `report.finding(severity, category, title, description, url)`

발견된 취약점을 리포트에 등록한다.

```lua
report.finding(
    "critical",           -- severity: critical / high / medium / low / info
    "custom",             -- category: xss / sqli / ssrf / traversal / cmdi / crlf / cors / custom
    "제목",               -- title
    "상세 설명",          -- description
    TARGET .. "/path"     -- url (선택, 생략 시 TARGET 사용)
)
```

#### `TARGET`

현재 스캔 대상 URL이 자동으로 주입된 전역 변수다.

```lua
print(TARGET)  -- "http://example.com"
```

### 차단된 API

다음은 샌드박스에서 차단된다.

```lua
io.open(...)      -- 파일 시스템 접근 불가
os.execute(...)   -- 시스템 명령 실행 불가
require(...)      -- 외부 모듈 로드 불가
```

### 예제 플러그인 모음

#### 백업 파일 탐지

```lua
-- scripts/backup_files.lua
local paths = {
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/dump.sql", "/site.tar", "/www.zip"
}

for _, path in ipairs(paths) do
    local resp = http.get(TARGET .. path)
    if resp.status == 200 and #resp.body > 100 then
        report.finding("high", "custom",
            "Backup File Exposed: " .. path,
            "Sensitive backup file is publicly accessible.",
            TARGET .. path
        )
    end
end
```

#### phpinfo 노출 탐지

```lua
-- scripts/phpinfo_check.lua
local resp = http.get(TARGET .. "/phpinfo.php")

if resp.status == 200 and resp.body:find("PHP Version") then
    report.finding("medium", "custom",
        "phpinfo() Exposed",
        "PHP configuration details are publicly visible.",
        TARGET .. "/phpinfo.php"
    )
end
```

#### 디렉터리 리스팅 탐지

```lua
-- scripts/dir_listing.lua
local dirs = {"/uploads/", "/files/", "/images/", "/static/", "/assets/"}

for _, dir in ipairs(dirs) do
    local resp = http.get(TARGET .. dir)
    if resp.status == 200
       and (resp.body:find("Index of") or resp.body:find("Parent Directory")) then
        report.finding("medium", "traversal",
            "Directory Listing Enabled: " .. dir,
            "Directory index is exposed, file enumeration is possible.",
            TARGET .. dir
        )
    end
end
```

---

## 7. 리포트 분석

### 리포트 파일 구조

```json
{
  "sentinel_version": "0.1.0",
  "target": "http://example.com",
  "scan_timestamp": "2026-03-20T10:30:00Z",
  "summary": {
    "total": 5,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1,
    "info": 1
  },
  "findings": [ ... ]
}
```

### 개별 Finding 구조

```json
{
  "id": "uuid-v4",
  "severity": "high",
  "category": "sql_injection",
  "title": "Potential SQLi in parameter 'id'",
  "description": "SQL error signature found when injecting payload '''",
  "url": "http://example.com/item?id='",
  "evidence": "Payload: '",
  "cve": null,
  "remediation": "Use parameterized queries / prepared statements",
  "timestamp": "2026-03-20T10:31:05Z"
}
```

### jq로 빠른 분석

```bash
# 심각도 High 이상만 필터
jq '.findings[] | select(.severity == "high" or .severity == "critical")' report.json

# 카테고리별 개수 집계
jq '[.findings[].category] | group_by(.) | map({(.[0]): length}) | add' report.json

# URL 목록만 추출
jq -r '.findings[].url' report.json | sort -u

# 요약만 출력
jq '.summary' report.json
```

---

## 8. 배포 관리

### Makefile 주요 명령

```bash
make build        # 개발 빌드
make release      # 릴리즈 빌드 (최적화 + strip)
make test         # 전체 테스트 (26개)
make lint         # clippy --deny warnings
make fmt          # rustfmt 자동 포매팅
make check        # fmt-check + lint + test
make install      # /usr/local/bin/sentinel 설치
make uninstall    # 설치 제거
make docker       # Docker 이미지 빌드
make clean        # target/ 및 출력 파일 삭제
```

### GitHub Actions 릴리즈 배포

```bash
# Cargo.toml 버전 수정 후 태그를 push하면 자동 배포
vim Cargo.toml          # version = "0.2.0"
git add Cargo.toml Cargo.lock
git commit -m "bump version to 0.2.0"
git tag v0.2.0
git push origin main --tags
```

워크플로가 자동으로:
1. Linux AMD64 / macOS AMD64 / macOS ARM64 바이너리 빌드
2. `.tar.gz` 아카이브 생성 + SHA256 체크섬 계산
3. GitHub Release 페이지에 게시

### Docker 이미지 관리

```bash
# 특정 버전 태그
docker build -t sentinel:0.2.0 -t sentinel:latest .

# docker-compose로 scripts 디렉터리 핫리로드
docker compose run sentinel --target http://example.com
# scripts/ 디렉터리를 수정하면 다음 실행에 즉시 반영 (볼륨 마운트)
```

---

## 9. 트러블슈팅

### Chrome을 찾을 수 없음 (`--browser` 사용 시)

```
Error: Failed to launch Chrome
```

해결:
```bash
# Chrome/Chromium 경로 확인
which chromium-browser || which google-chrome

# 없으면 설치
sudo apt-get install chromium-browser

# Docker 사용 시 이미지에 Chromium 포함되어 있음
make docker && make docker-run ARGS="--target http://example.com --browser"
```

### 너무 느린 스캔

1. `--no-ports`로 포트 스캔 생략
2. `--rps`와 `--threads`를 높여라

```bash
sentinel --target http://example.com --no-ports --threads 200 --rps 50
```

### 스코프 오류로 결과가 없음

```
Target http://app.example.com is out of scope, skipping
```

`--scope`를 명시적으로 지정:
```bash
sentinel --target http://app.example.com --scope example.com
```

### Lua 스크립트 오류 확인

```bash
sentinel --target http://example.com -vv 2>&1 | grep "Script"
```

`-vv` 모드에서 각 스크립트의 실행 오류가 출력된다.

### 연결 타임아웃이 많이 발생

```bash
sentinel --target http://slow-target.com --timeout 30 --rps 3 --threads 10
```

### GitHub Actions 빌드 실패

```bash
# 로컬에서 동일한 검사 실행
make check

# 특정 단계만 실행
cargo fmt --check
cargo clippy -- -D warnings
cargo test --locked
```

---

## 10. 보안 주의사항

1. **승인된 대상에만 사용** — 무단 스캔은 법적 책임이 따른다.
2. **RPS 제한 준수** — 운영 중인 서비스에는 `--rps 5` 이하 권장.
3. **스코프 확인** — `--scope`가 의도한 도메인으로 설정되었는지 항상 확인.
4. **리포트 파일 보안** — JSON 리포트에는 민감한 취약점 정보가 포함되므로 접근 제어 필요.
5. **Lua 스크립트 검토** — 외부에서 받은 Lua 플러그인은 실행 전 코드 검토 필수.
6. **Docker 볼륨 권한** — `output/` 디렉터리에 취약점 정보가 저장되므로 호스트 권한 설정 필요.
