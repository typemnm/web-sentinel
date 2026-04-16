# OWASP Juice Shop 스캔 결과 리포트

> **스캔 일시**: 2026-03-24
> **대상**: OWASP Juice Shop (Docker `bkimminich/juice-shop`, localhost:3000)
> **스캐너**: Sentinel v0.2.0 (모든 개선 사항 적용)
> **설정**: `--no-ports --rps 20 --threads 30 --crawl-depth 4 --crawl-max-urls 200 --thorough`

---

## 1. 요약

| 심각도 | 자동 탐지 | 수동 확인 추가 |
|--------|-----------|----------------|
| Critical | 1 | 2 |
| High | 1 | 4 |
| Medium | 4 | 0 |
| Low | 4 | 0 |
| Info | 9 | 0 |
| **합계** | **19** | **6** |

### 개선 전후 비교

| 지표 | v0.2.0 (초기) | v0.2.0 (개선 후) |
|------|---------------|------------------|
| 총 탐지 수 | 38 | 19 |
| 오탐 수 | ~18 | 0 |
| 정탐 수 | ~20 | 19 |
| 크롤러 발견 엔드포인트 | 0 | 15+ |
| 프레임워크 식별 | Django (오탐) | 탐지 없음 (Express 미노출) |

---

## 2. 자동 탐지 결과 (Sentinel)

### Critical

| # | 제목 | URL | 설명 |
|---|------|-----|------|
| 1 | SSTI in /render (Handlebars) | `http://localhost:3000/render` | Handlebars 템플릿 인젝션. `{{913*773}}` → `705649` 평가 확인. 서버 사이드 코드 실행 가능. |

### High

| # | 제목 | URL | 설명 |
|---|------|-----|------|
| 2 | Mass Assignment (/api/users) | `http://localhost:3000/api/users` | POST 요청 시 `role`/`admin` 필드가 수락 및 반영됨. 권한 상승 가능. |

### Medium

| # | 제목 | URL | 설명 |
|---|------|-----|------|
| 3 | CORS: wildcard origin (*) | `http://localhost:3000` | `Access-Control-Allow-Origin: *` 설정. 모든 오리진에서 API 응답 읽기 가능. |
| 4 | Source Map: main.js.map | `http://localhost:3000/main.js.map` | JavaScript 소스맵 노출. 원본 소스 코드 재구성 가능. |
| 5 | Source Map: polyfills.js.map | `http://localhost:3000/polyfills.js.map` | 상동 |
| 6 | Source Map: scripts.js.map | `http://localhost:3000/scripts.js.map` | 상동 |

### Low

| # | 제목 | URL | 설명 |
|---|------|-----|------|
| 7 | Missing: Content-Security-Policy | `http://localhost:3000` | CSP 미설정. XSS 공격 완화 불가. |
| 8 | Missing: Strict-Transport-Security | `http://localhost:3000` | HSTS 미설정. |
| 9 | Missing: Referrer-Policy | `http://localhost:3000` | Referer 헤더로 토큰/경로 유출 위험. |
| 10 | Missing: Permissions-Policy | `http://localhost:3000` | 브라우저 기능 제한 미설정. |

### Info

| # | 제목 | 설명 |
|---|------|------|
| 11-19 | Upload Endpoint Found (9건) | `/upload`, `/avatar`, `/admin/upload`, `/cms/upload`, `/editor/upload`, `/file/upload`, `/image/upload`, `/media/upload`, `/profile/photo` |

---

## 3. 수동 확인 결과

Sentinel 자동 탐지 외에 수동으로 확인한 추가 취약점:

### Critical

#### 3.1 SQL Injection — `/rest/user/login`

```bash
curl -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"' OR 1=1--","password":"test"}'
```

**결과**: admin 계정(admin@juice-sh.op)의 JWT 토큰 반환. 인증 우회 성공.

- 반환된 JWT로 `/api/Users` 접근 → 30개 전체 사용자 목록 열거 (8개 admin 계정 포함)
- admin 역할의 이메일: `admin@juice-sh.op`, `bjoern.kimminich@gmail.com`, `support@juice-sh.op`, `J12934@juice-sh.op`, `wurstbrot@juice-sh.op`, `bjoern@juice-sh.op`, `testing@juice-sh.op`

#### 3.2 Null-byte Path Traversal — `/ftp/`

```bash
curl "http://localhost:3000/ftp/eastere.gg%2500.md"
```

**결과**: `.md` 확장자 제한을 null-byte(`%2500`)로 우회하여 `eastere.gg` 파일 내용 접근 성공.

- Easter egg 체인: Base64 → ROT13 → 숨겨진 경로 `/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`

### High

#### 3.3 FTP 디렉터리 리스팅

```
http://localhost:3000/ftp/
```

**노출된 파일:**
- `acquisitions.md` — 기밀 인수 계획 문서 ("This document is confidential!")
- `incident-support.kdbx` — KeePass 데이터베이스 파일
- `package.json.bak` / `package-lock.json.bak` — 의존성 정보
- `coupons_2013.md.bak` — 쿠폰 코드
- `encrypt.pyc` — Python 바이트코드
- `suspicious_errors.yml` — 에러 로그

#### 3.4 보안 질문 API 미인증 접근

```bash
curl http://localhost:3000/api/SecurityQuestions
# → 전체 보안 질문 목록 반환 (비밀번호 재설정 공격에 활용 가능)
```

#### 3.5 챌린지 API 노출

```bash
curl http://localhost:3000/api/Challenges
# → 111개 전체 챌린지 목록 + 풀이 상태 반환 (스코어보드 노출)
```

#### 3.6 사용자 열거

SQL Injection으로 획득한 admin JWT를 사용하여 전체 사용자 목록 접근 가능.
30개 계정 (admin 8, customer 14, deluxe 4, accounting 1, 기타).

---

## 4. 제거된 오탐 (v0.2.0 → v0.2.0)

| # | 이전 탐지 | 원인 | 수정 사항 |
|---|-----------|------|-----------|
| 1 | SSTI `{{7*7}}` via `?message=` | "49"가 Angular 빌드 코드에 자연 존재 | `913*773=705649` + 베이스라인 체크 |
| 2-16 | Backup files 15건 (.zip, .sql, .tar 등) | SPA가 모든 경로에 200+HTML 반환 | SPA 감지 + Content-Type 검증 |
| 17 | `.htpasswd` 크리티컬 | `":"` 시그니처가 모든 HTML에 매칭 | `$apr1$`/`{SHA}`/`$2y$` 해시 패턴 |
| 18 | Django 프레임워크 탐지 | `X-Frame-Options: SAMEORIGIN` 헤더가 범용적 | body-only 시그니처로 변경 |

---

## 5. 결론 및 권고

### Juice Shop에 대한 권고 (교육 목적)

1. **즉시 조치**: SQL Injection 패치 (Parameterized Query 사용)
2. **인증 강화**: API 엔드포인트에 인증 미들웨어 적용 (`/api/SecurityQuestions`, `/api/Challenges`)
3. **FTP 접근 제어**: 디렉터리 리스팅 비활성화, 민감 파일 제거
4. **헤더 보안**: CSP, HSTS, Referrer-Policy 추가
5. **CORS 제한**: 와일드카드(*) → 신뢰할 수 있는 오리진만 허용
6. **소스맵 제거**: 프로덕션 빌드에서 `.js.map` 파일 제거

### Sentinel 성능 평가

- SPA 대상 크롤링이 JS 엔드포인트 추출로 크게 개선됨
- 오탐률 47% (18/38) → 0% (0/19)으로 대폭 개선
- Mass Assignment, SSTI(Handlebars) 등 실제 취약점 정확 탐지
- SQL Injection(POST JSON), null-byte traversal 등은 현재 미탐지 → 향후 개선 대상
