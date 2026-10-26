# ADR-S4-02: validation-api — 지표 조회 서비스 구조·권한·계약

- 상태: Accepted (2026-10-20, DRI 이현성)
- 개정 v1.1 (2026-10-20): 기준 버전 점검 결과 반영 — validation-api를 Spring Boot 4.1.x·Spring Security 7.x로 변경(3.5 OSS 지원 종료),
  D4 오류 응답 일관성 보강, D5를 Boot 4.1 SSL 문서 기준으로 갱신, 알려진 한계 섹션 추가(현성 DRI, 기준 e1220d6).
- 개정 v1.2 (2026-10-21): backend는 ADR-S4-03 v1.3(슬라이스 5)으로 develop-v2에서 삭제됨. 이 문서의 backend 언급은 결정 당시 기준
- 개정 v1.3 (2026-10-22): S4-6 착수 — D4 엔드포인트 확정(/api/v1/*)·D6 브라우저 인증 보강·D8 SBOM 도구 확정(CycloneDX)·D2 GRANT 확정,
  신설 D9(정적 서빙·CSP)·D10(프런트 빌드)·D11(출처 보존 run_provenance_note). /compare·/snapshot 의미, Configuration Change = rules_digest + engine_version.
  대시보드 표시 규칙은 별도 ADR-S4-04. 근거는 ADR-S4-04 근거 목록과 공유(현성 DRI).
- DRI: 이현성 / C: 없음(D7 독립 검토로 대체)
- 기준 커밋: e9430ec
- 근거 등급: 1차=원문 확인 / 2차=해석 글 교차 / 해석=우리 적용

## 맥락
validation-api는 ADR-S4-01 계획상 S4-6이다. 이 ADR은 구현 전에 결정을 고정한다(사전 정의).
- 루트는 단일 Gradle 프로젝트 vulnerable-webapp (Java 17, Spring Boot 3.5.13, Gradle 8.14.4).
- 2026-10-20 기준 버전 점검: Spring Boot 현재 GA는 4.1.1. 3.5는 OSS 지원 2026-06-30 종료, 4.0은 2026-12-31 종료.
  target-web(3.5.13)의 업그레이드 여부는 별도 크기 측정 후 결정한다(이 ADR 범위 밖).
- validation 스키마: 테이블 8·뷰 12·함수 4, 소유자 모두 validation_rw. 뷰 reloptions NULL(security_invoker=false).
- wilson_ci·quantile_t8는 V3에서 PUBLIC EXECUTE 회수됨. 트리거 함수 2개(verdict_history_append_only,
  verdict_result_reject_closed_run)는 proacl NULL(PUBLIC EXECUTE 기본값).
- pg_default_acl 0행. 읽기 전용 role 없음.
- 저장소에 ATT&CK 버전 표기 0건.

## 결정

### D1 위치
- 저장소 루트 `validation-api/` 에 독립 Gradle 빌드(자체 settings.gradle·wrapper). 버전: Java 17, Spring Boot 4.1.x(4.1 라인 최신 패치), Gradle 8.14.4.
  target-web과 버전을 맞추지 않는다 — 지원이 끝난 구성요소를 새 서비스에 쓰지 않는다(D8, OWASP A03:2025).
- 루트 프로젝트 무변경(멀티 프로젝트 전환 안 함), backend(`docker/services/backend`) 무변경.
- API는 마이그레이션을 실행하지 않음(Flyway는 target-web의 ValidationSchemaMigrator만).
- 근거:
  - (1차) Gradle 공식 문서 Composite Builds — 포함 빌드는 서로 설정을 공유하지 않으며 라이브러리·소비자를 함께 개발할 때 쓰는 방식.
    validation-api는 루트 빌드와 의존 관계가 없으므로 멀티 프로젝트·컴포지트 모두 불필요.
  - (해석) 취약 앱과 측정 평면을 산출물·컨테이너·DB role로 분리 — ISMS-P 분리 원칙 적용.
  - (1차) Spring Boot 4.1 System Requirements — Java 17 이상(25까지 호환), Gradle 8.14 이상의 8.x 또는 9.x → 현재 Java 17·Gradle 8.14.4 그대로 사용 가능.
  - (2차) Spring Boot 3.5 OSS 지원 2026-06-30 종료(Spring Framework 6.2·Spring Security 6.5 함께 종료), 4.0은 2026-12-31 종료 → 4.1 선택.

### D2 DB 읽기 전용 role
- 이름 validation_ro. 속성: LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, default_transaction_read_only=on.
- 숫자 값은 이 ADR에서 확정하지 않음:
  · statement_timeout = S4-6 role 슬라이스에서 공개 뷰 8개를 운영 데이터로 EXPLAIN (ANALYZE) 실측한 뒤 값·근거를 기록해 확정.
  · CONNECTION LIMIT = API 커넥션 풀 최댓값 + 1(운영 점검용). 풀 최댓값은 S4-6 API 슬라이스에서 결정.
- 비밀번호: bootstrap 스크립트에 psql 변수로 주입(.env VALIDATION_RO_DB_PASSWORD). 기존 app_role.sql·validation_role.sql 방식과 동일.
- 객체 권한은 권한 부여 마이그레이션에서 부여(번호는 S4-6 착수 시점의 다음 번호). v1.3 확정:
  · USAGE ON SCHEMA validation
  · SELECT on 공개 뷰 + `v_api_attempt`(허용 컬럼만 노출하는 새 뷰) + `metric_snapshot` · `metric_snapshot_withdrawal` · `measurement_run`
  · EXECUTE on `wilson_ci` · `quantile_t8` · `newcombe_diff_ci`(모두 C7에서 PUBLIC EXECUTE 회수 확인됨 — 회수된 함수만 명시 부여)
  · 기반 테이블(공개 뷰·v_api_attempt 가 읽는)과 중간 뷰는 부여하지 않음(뷰는 security_invoker=false 로 소유자 권한 읽기).
  · DEFAULT PRIVILEGES 금지(쓰면 기반 테이블까지 열림).
  · `default_transaction_read_only=on` 은 보조 장치일 뿐 보안 경계가 아니다(세션에서 해제 가능). 실제 경계 = 쓰기 권한 없음.
- 근거:
  - (1차) PostgreSQL 16 CREATE VIEW — security_invoker=false 뷰는 기반 테이블을 뷰 소유자 권한으로 접근하고,
    뷰 안의 함수는 조회 사용자가 직접 호출한 것처럼 취급되므로 EXECUTE 필요.
  - (2차) CYBERTEC pgconfigurator statement_timeout — 역할별 statement_timeout 권고(전역 일괄 적용 대신 역할·세션별로 짧게).
  - (해석) 최소 권한 원칙 적용.
  - (해석) Gartner Top Cybersecurity Trends 2026 ④ AI 에이전트용 IAM — validation_ro는 비인간 서비스 계정이므로 최소 권한·속성 제한을 적용.

### D3 권한 유지 규칙
- DEFAULT PRIVILEGES는 쓰지 않음(쓰면 기반 테이블까지 열림).
- 새 공개 뷰는 해당 마이그레이션에 GRANT를 명시.
- 테스트가 validation_ro의 실제 권한 = 허용 목록인지 검사(초과·누락 모두 실패). 이 테스트는 CI 게이트(빌드 실패 조건).
- 근거:
  - (1차) Magonia 'Five Year Retrospective on Detection as Code' — 테스트 없는 룰이 주요 실패 원인, 규칙은 테스트로 지킴.
  - (1차) SANS×Anvilogic 2026 탐지 엔지니어링 조사(n=307) — CI/CD 도입 42%로 최대 낙차.

### D4 API 계약
- GET 전용, 경로 `/api/v1/*` (v1.3 확정):
  - `/meta`
  - `/runs`, `/runs/{runId}`
  - `/snapshot` (definition_version 필터, 기본 최신 · 철회된 행 제외)
  - `/runs/{runId}/metrics/{name}` — name 은 허용 목록(rates·correlation·h2·mttd·coverage·attacker)
  - `/runs/{runId}/attempts?verdict=`
  - `/compare` — Before/After 비교
  - `/navigator-layer?layer=detection|visibility` — ATT&CK Navigator 레이어
- 비-VALID run 조회는 **409 problem+json**(무결성 상태만, 지표 미반환).
- `/compare`: `compare_snapshots` 함수 대신 **같은 definition_version 행끼리 직접 join + newcombe_diff_ci**(ADR-S4-01 R3 Wilson 재사용). before/after 정의가 다르면 **409**(측정 정의가 다른 run 은 비교 거부). Configuration Change 비교축 = **rules_digest + engine_version**.
- `/snapshot`: 기본 definition_version 최신, 철회된(metric_snapshot_withdrawal) 행 제외.
- 실시간 확인은 측정 DB 연결 자체뿐이고, 반환값은 모두 **"측정 당시"**(불변 스냅샷·측정 run 기록) 기준. 라이브 재계산 여부 표시는 ADR-S4-04 R-a.
- `/navigator-layer`: versions layer `"4.5"`, attack `"20.0"`(MITRE v19.2→v20.0 changelog 레이어 형식), navigator 값은 저장소 문서에서 확인하고 못 찾으면 `"5.0.0"`.
- 응답에 x, n, p, lo, hi, status, definition_version 포함. n=0이면 p·lo·hi는 null (ADR-S4-01 n=0 규칙).
  - 근거: (1차) Dmitriev 외, KDD 2017 'A Dirty Dozen'(Microsoft 실험 플랫폼) — 비율 지표는 분자·분모를 항상 함께 제시.
- 오류 응답: RFC 9457 Problem Details(application/problem+json). `spring.mvc.problemdetails.enabled=true`를 명시한다(Boot 4 기본값 여부에 의존하지 않음).
  이 속성은 Spring MVC가 처리하는 예외만 변환하므로, 그 밖의 예외(500)와 오류 컨트롤러 경로도 problem+json이 되도록 전역 예외 처리기를 둔다.
  인증 실패 401은 D6의 AuthenticationEntryPoint가 담당한다.
  - 근거: (1차) RFC 9457(2023-07, RFC 7807 대체). (2차) spring-boot GitHub 이슈 #35701·#48392 — 속성을 켜도 임의 예외의 500과
    BasicErrorController 응답은 기존 형식으로 나옴.
- SQL은 바인딩 파라미터만(CWE-89). runId는 UUID, split_kind·verdict는 허용 목록 검증.
- 목록 상한은 고정값이 아니라 설정값. 기본값은 "현재 최대 run의 시도 수" 실측 기준으로 S4-6 API 슬라이스에서 결정.
- OpenAPI 문서 제공. actuator는 health만 노출.
- (1차) OWASP API Security Project — API Security Top 10 2023(2023-06-05 정식 공개, 2026-10-20 기준 최신판) 매핑:
  - API1 모든 run은 같은 읽기 권한 범위(객체별 소유자 없음)임을 명시
  - API2 → D6
  - API3 계약에 명시한 필드만 반환, SELECT * 금지
  - API4 statement_timeout + 목록 상한
  - API8 오류 응답에 스택트레이스·SQL 미노출, actuator는 health만
  - API9 OpenAPI 문서 + /api/v1 버전 경로
- (1차) OWASP Top 10:2025(2025-11 발표·2026-01 확정, 웹 애플리케이션 최신판). API 2023 목록과 서로 대체하지 않으므로 함께 적용:
  - A01 접근 통제 → D2·D6 / A02 보안 설정 → API8 항목 / A04 암호화 → D5 HTTPS / A05 인젝션 → 바인딩 파라미터(CWE-89) / A07 인증 → D6
  - A03 공급망 → D8 / A09 로깅·알림 → D6 추가 항목 / A10 예외 처리 → 아래 항목
- A10 예외 처리(fail-closed): DB 오류·statement_timeout 초과 시 503 application/problem+json.
  부분 계산값·이전 값은 반환하지 않음. 오류 응답에 내부 정보 미노출(API8과 동일).
- 조회 대상(라이브 뷰 vs metric_snapshot): S4-3 metric_snapshot 도입 결과에 의존하므로
  S4-6 착수 시 이 ADR 개정으로 확정한다. 확정 전에는 구현하지 않는다.

### D5 배포·전송
- compose 서비스 validation-api, 네트워크 app_net만(attack_net·imds_net·security_net 제외), 포트 127.0.0.1:8090, 비루트 사용자 이미지.
- HTTPS만 제공(평문 HTTP 포트 열지 않음).
  · Spring Boot SSL 번들: `spring.ssl.bundle.pem.<이름>`에 인증서·개인키(PEM), `server.ssl.bundle=<이름>`.
    server.ssl의 개별 keystore/PEM 속성과 섞지 않음(공식 문서상 병용 불가).
  · 인증서는 자체 서명(로컬 랩), 현성이 openssl로 생성. 개인키는 git 제외, 경로는 .env로 주입.
  · TLS 프로토콜·암호군은 `spring.ssl.bundle.pem.<이름>.options`로 지정한다(번들 사용 시 server.ssl.ciphers·enabled-protocols·protocol은 무시됨).
- 근거:
  - (1차, 구 위키판) OWASP REST Security Cheat Sheet — REST 서비스는 HTTPS 엔드포인트만 제공(자격 증명 전송 보호).
  - (1차) NIST SP 800-207 — 네트워크 위치와 무관하게 통신 보호.
  - (2차) ISMS-P 강화방안 외부 연결 지점 최소화(2026-04 보도, 고시 원문 미열람; S0 포트 원칙과 동일).
  - (1차) Spring Boot 4.1 How-to "Embedded Web Servers — Configure SSL / Using SSL Bundles" — server.ssl.bundle은 server.ssl의 개별 KeyStore·PEM 속성과 병용 불가,
    번들 사용 시 ciphers·enabled-protocols·protocol은 무시되므로 spring.ssl.bundle.<type>.<이름>.options로 지정. Spring 블로그(SSL 번들, Boot 3.1 도입).
- PQC: (해석) Gartner 2026 Top Cybersecurity Trends ③ PQC 실행계획(2030년 비대칭 암호 불안전 예측)과 충돌 없음.
  로컬 랩 자체 서명 HTTPS이며, PQC 전환은 JDK·TLS 라이브러리 지원에 따른 플랫폼 과제로 범위 밖.
  전환 대상 목록(암호 자산 인벤토리)에 "validation-api TLS"를 기록.

### D6 인증
- v1.3 보강 — 두 가지 주체:
  · 브라우저(대시보드) = **formLogin + 세션 쿠키**(HttpOnly·Secure·SameSite=Strict). 토큰을 JS·브라우저 저장소(localStorage 등)에 두지 않는다.
  · smoke·capture 스크립트 = **Bearer 토큰**(아래). 사람 브라우저 경로에는 쓰지 않는다.
  · SecurityFilterChain **2개**: `@Order(1)` `/api/**`(Bearer·stateless), `@Order(2)` UI(formLogin·세션). 무인증 경로는 `/actuator/health` 하나뿐.
- 인증 필수. Bearer 토큰, 클라이언트별로 하나씩 발급해 .env로 주입(변수 이름 규칙은 S4-6 API 슬라이스에서 결정).
- 토큰은 `Authorization: Bearer` 헤더로만 받음. 쿼리 파라미터·URL 금지(서버 로그 노출 방지).
- 비교는 상수 시간(MessageDigest.isEqual 등).
- 구현: OncePerRequestFilter를 상속한 인증 필터를 SecurityFilterChain에서 LogoutFilter 뒤에 등록.
  필터를 @Component·@Bean으로 선언하지 않음. 빈이 필요하면 FilterRegistrationBean(enabled=false)로 컨테이너 자동 등록을 막음(이중 실행 방지).
  인증 실패 → AuthenticationException → AuthenticationEntryPoint가 401 application/problem+json 응답.
- /actuator/health만 무인증(상태값만 노출, compose healthcheck용).
- 데이터 등급: 비민감 집계값 → API 키 방식 허용 범위. 민감 데이터가 추가되면 재검토.
- 재검토 조건: 호스트 밖으로 노출할 때 OAuth2 client credentials로 전환 검토.
- 인증 필터에서 예외가 나면 거부로 처리(fail-closed, OWASP A10:2025).
- 인증 실패·입력 검증 거부를 구조화 로그로 기록. 토큰 값·Authorization 헤더는 기록하지 않음(OWASP A09:2025).
- (해석) 이 로그는 탐지 신호로 Wazuh 수집 대상이 될 수 있음. 수집 여부는 이 ADR 범위 밖.
- 근거:
  - (1차) NIST SP 800-207 — 네트워크 위치만으로 암묵적 신뢰 금지.
  - (1차) NIST SP 800-207A — 애플리케이션·서비스 신원 기반 인증·인가.
  - (1차) OWASP API Security Top 10 2023 API2:2023 Broken Authentication.
  - (1차, 구 위키판) OWASP REST Security Cheat Sheet — 보호 엔드포인트의 모든 요청에 키 요구, 민감·고가치 자원은 API 키 단독 금지,
    키를 URL에 넣지 않음.
  - (1차) Spring Security 7.1 공식 레퍼런스 Architecture "Adding a Custom Filter"(6.5와 내용 동일 확인).
  - (1차) Spring Boot 4.1 How-to "Disable Registration of a Servlet or Filter" — FilterRegistrationBean.setEnabled(false)로 컨테이너 자동 등록 해제.
  - (해석) Gartner Top Cybersecurity Trends 2026 ④ AI 에이전트용 IAM — 나중에 에이전트·대시보드가 호출할 때 호출자 신원 필요.

### D7 검토 체계 (계획서 DACI 변경)
- DB Schema C(오정현) 폐기.
- 대체: 작성 맥락이 없는 새 Claude Code 채팅이 체크리스트로 독립 검토 → DRI(이현성) 승인.
- 팀 origin 반영은 독립 검토 통과 후.
- ADR-S4-01의 헤더 DRI 줄 C(오정현)와 결과(Consequences)의 push 전 오정현 리뷰 규칙을 대체한다.
- 근거:
  - (1차) Magonia 'Five Year Retrospective on Detection as Code' — LLM은 저위험 감사에 사용.
  - (1차) Microsoft Security Blog(2026-04-09) Agentic SOC — 사람이 의도·판단·책임.
  - (1차) 토스 팀 문화(toss.im/tossfeed) DRI — 듣고 결정, 결정 후 함께 실행. DACI 변경은 이 ADR로 기록.

### D8 공급망
- 요구사항(지금 고정): 의존성 버전 고정, 빌드 시 SBOM 생성, 알려진 취약점 검사(빌드 실패 기준은 S4-6에서 정함).
- 도구(v1.3 확정): Gradle 플러그인 **`org.cyclonedx.bom`** 로 빌드 때 CycloneDX SBOM 생성, 이미지에 포함. 플러그인 버전은 **Spring Boot 4.1 공식 문서(build-tool-plugins/dependency-versions)에 명시된 값으로 고정**(구현 Step 1에서 확인·추측 금지).
- actuator 는 **health 만** 노출하고 `sbom` 엔드포인트는 노출하지 않는다(SBOM 은 파일로만 보관).
- 근거:
  - (1차) OWASP Top 10:2025 A03 Software Supply Chain Failures — 의존성·빌드 시스템·배포 인프라 전체로 범위 확장.
  - (해석) Gartner Top 10 Strategic Technology Trends 2026 디지털 출처 증명(SBOM·증명) 적용.

### D9 정적 서빙·CSP (v1.3)
- 대시보드 정적 자원은 validation-api 와 **같은 출처**에서 서빙(별도 오리진 없음 → CORS 불필요).
- CSP: `default-src 'self'; script-src 'self'`(`unsafe-eval` 없음); `style-src 'self'`; `img-src 'self' data:`; `frame-ancestors 'none'`.
- 근거: (1차) OWASP Top 10:2025 A02 보안 설정 / CSP. 인라인 `style`·`script`·`eval` 을 쓰지 않는 자산만 서빙한다.
- **S4-6**: vega 차트(vega-embed)는 렌더 시 인라인 `<style>` 를 주입해 `style-src 'self'` 와 충돌했다 → **플랫폼 자체 보안을 위해 CSP 를 느슨히 하지 않고 vega 차트·의존성을 제거**(DiffChart·RangeChart·VegaChart, `vega*` deps). 파비콘은 인라인 `data:` SVG(`img-src ... data:`)로 `/favicon.ico` 요청 자체를 제거.

### D10 프런트 빌드 (v1.3)
- Dockerfile **다단계** 빌드, node 이미지 **digest 고정**, `npm ci --ignore-scripts`, lockfile 커밋, `npm audit` 결과를 증거 로그로 남긴다.
- 프런트 스택 버전은 구현 Step 1에서 실측 고정(ADR-S4-04).
- 근거: (1차) OWASP Top 10:2025 A03 — 빌드 스크립트 실행 차단(--ignore-scripts)·lock 고정. (해석) D8 과 같은 공급망 원칙.

### D11 출처 보존 (v1.3)
- `measurement_run` 은 수정하지 않는다. 스택 버전 등 출처는 **V11 append-only 표 `run_provenance_note`**:
  · 컬럼: `run_id`(FK) · `item` · `value` · `source_file` · `source_line` · `recorded_at`
  · UPDATE·DELETE·TRUNCATE 차단 트리거(metric_snapshot 와 같은 방식).
  · **커밋된 증거 로그에 있는 값만 INSERT**. 원천이 없으면 넣지 않고 화면에는 "기록 없음".
- 근거: (해석) Gartner 2026 디지털 출처 증명. (1차) 불변 기록층 — ADR-S4-01 R13 metric_snapshot 와 같은 append-only 원칙.

## 알려진 한계 (근거)
- Spring Boot 3.5·4.0 OSS 지원 종료일은 2차(자료 4곳 일치). spring.io 지원 표는 직접 읽지 못함.
  현재 GA가 4.1.1이라는 것은 1차이므로 '4.1 선택' 결정에는 영향 없음.
- Boot 4의 Jackson 3 전환은 공식 마이그레이션 가이드(1차)로 '전환 사실'만 확인. JSON 출력 형식이 얼마나 바뀌는지는 2차.
  → validation-api는 S4-6 API 슬라이스에서 응답 계약 테스트로 실측 확인.
- Boot 4에서 ProblemDetail이 기본 활성인지는 2차 → 기본값에 의존하지 않고 명시 설정(D4).

## 알려진 공백 (이 ADR 범위 밖)
- 기존 스택 내부 연결(target-web·backend ↔ PostgreSQL 등)은 평문. validation-api ↔ PostgreSQL도 같은 상태로 시작.
  known-gaps.md에 별도 Gap으로 기록할 후보(이번 슬라이스에서는 기록·수정 안 함).
- vulnuser 슈퍼유저(Gap #3 범위, 이번 슬라이스에서 다루지 않음).

## 하지 않은 것
멀티 프로젝트 전환, backend 수정, vulnuser 권한 변경, 기존 스택 DB 연결 TLS. (SBOM 도구는 v1.3 D8에서 CycloneDX로 확정 — 취약점 검사 빌드 실패 기준은 S4-6 구현에서 정함.)

## 출처
근거 등급과 출처를 남기는 이유: (1차) 토스 팀 문화 — 정보 공유가 좋은 결정의 전제(DRI가 듣고 결정),
(1차) Gartner Top Cybersecurity Trends 2026 ① 에이전틱 AI 감독 — 이 문서는 AI 초안을 사람이 검토해 확정하므로
근거 강도와 출처를 검증 가능하게 둔다, (해석) Gartner 2026 디지털 출처 증명을 문서 근거에 적용.

1차
- PostgreSQL 16 CREATE VIEW — https://postgresql.org/docs/16/sql-createview.html
- Gradle Composite Builds — https://docs.gradle.org/current/userguide/composite_builds.html
- RFC 9457 Problem Details for HTTP APIs — https://www.rfc-editor.org/info/rfc9457
- NIST SP 800-207 — https://csrc.nist.gov/Pubs/sp/800/207/Final
- NIST SP 800-207A — https://csrc.nist.gov/pubs/sp/800/207/a/final
- OWASP API Security Project(Top 10 2023, 최신판 확인 2026-10-20) — https://owasp.org/www-project-api-security/
- OWASP Top 10:2025 — https://owasp.org/Top10/2025/0x00_2025-Introduction/
- OWASP REST Security Cheat Sheet(구 위키판) — https://wiki.owasp.org/index.php?title=REST_Security_Cheat_Sheet
- Spring Boot 4.1 How-to: Embedded Web Servers(Configure SSL, Disable Registration) — https://docs.spring.io/spring-boot/how-to/webserver.html
- Spring 블로그 Securing Spring Boot Applications With SSL(2023-06-07) — https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl
- Spring Security 7.1 Reference: Architecture — https://docs.spring.io/spring-security/reference/servlet/architecture.html
- MITRE ATT&CK Updates(v20, 2026-10-13) — https://attack.mitre.org/resources/updates/
- Spring Boot 4.1 System Requirements — https://docs.spring.io/spring-boot/4.1/system-requirements.html
- Spring Boot 프로젝트 페이지(현재 GA 4.1.1 확인) — https://spring.io/projects/spring-boot
- Spring Boot 4.0 Migration Guide — https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide
- Magonia "Five Year Retrospective on Detection as Code", SANS×Anvilogic 2026 조사, Microsoft Security Blog Agentic SOC(2026-04-09),
  Dmitriev 외 KDD 2017 "A Dirty Dozen", 토스 팀 문화 글, Gartner Top Cybersecurity Trends 2026(2026-02-05),
  Gartner Top 10 Strategic Technology Trends 2026 — 이전 조사(캡스톤 방법론 기록)에서 확인, URL 미기재
2차
- CYBERTEC pgconfigurator: statement_timeout — https://pgconfigurator.cybertec-postgresql.com/docs/parameters/statement_timeout
- Spring Boot 3.5·4.0 OSS 지원 종료일 — https://endoflife.ai/article-spring-june-30-eol-wave , https://www.danvega.dev/blog/spring-boot-end-of-life
- spring-boot GitHub 이슈 #35701 — https://github.com/spring-projects/spring-boot/issues/35701
- spring-boot GitHub 이슈 #48392 — https://github.com/spring-projects/spring-boot/issues/48392
- ISMS-P 인증제 실효성 강화방안 보도(2026-04-10) — 이전 조사에서 확인, URL 미기재

## 렌즈 대조표 (맺음말)
| 결정 | 표준·규제 | 기술별 | 기업별 | 2026 트렌드 |
|---|---|---|---|---|
| D1 | ISMS-P 분리 원칙 (해석), OWASP Top 10:2025 A03 | Gradle Composite Builds, Spring Boot 4.1 System Requirements | 토스 범위 축소·깊이 우선, TRIZ 공간 분리 | Gartner AEV 결과 연동 (해석) |
| D2 | 최소 권한 (해석) | PostgreSQL 16 CREATE VIEW, 역할별 statement_timeout (2차) | 토스식 사전 정의(숫자는 실측) | Gartner 2026 ④ AI 에이전트용 IAM — 비인간 서비스 계정 최소 권한 (해석) |
| D3 | 최소 권한 (해석) | DaC 테스트 | S-Cube 정착=표준화 | SANS 2026 CI 낙차 |
| D4 | OWASP API 2023, OWASP Top 10:2025(A02·A05·A10), RFC 9457, CWE-89 | ProblemDetail 명시 설정 + 전역 예외 처리기 (2차, Spring Boot 이슈) | Microsoft 실험 플랫폼 관행(KDD 2017) — 분자·분모 병기 | RFC 9457 채택 확산 |
| D5 | OWASP REST CS, NIST 800-207, ISMS-P (2차) | Spring Boot 4.1 SSL 번들 | 해당 없음 — 기업 프레임워크는 진행 방식 근거로만 사용(2026-10-10 근거 사용 원칙), 전송 암호화는 기술 선택 | Gartner 2026 ③ PQC — 충돌 없음, 인벤토리 기록 (해석) |
| D6 | NIST 800-207·207A, OWASP API2:2023·REST CS, OWASP Top 10:2025(A07·A09·A10) | Spring Security 7.1 커스텀 필터, Spring Boot 4.1 FilterRegistrationBean | 토스 DRI 결정 | Gartner 2026 ④ AI 에이전트용 IAM (해석) |
| D7 | 해당 없음 — 조직 운영 결정이라 기술 표준이 정하는 영역 아님 | 해당 없음 — 특정 기술에 의존하지 않는 검토 절차 | 토스 DRI, DACI 변경 기록 | Magonia DaC 회고 LLM 감사, MS Agentic SOC, Gartner 2026 ① 에이전틱 AI 감독 |
| D8 | OWASP Top 10:2025 A03 | S4-6에서 공식 문서로 도구 선택 | 토스식 사전 정의(요구사항 먼저) | Gartner 2026 디지털 출처 증명 (해석) |
