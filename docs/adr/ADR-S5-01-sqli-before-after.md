# ADR-S5-01: SQLi 미탐 룰 개선 Before/After (Gap #7, 1사례)

- 상태: Accepted (2026-10-22) — Part B(룰 작성·테스트) 결과를 보기 전에 작성·단독 커밋(측정 전 설계 고정, Kohavi 가드레일 사전 선언).
- DRI: 이현성 / C: 오정현(Schema·Metrics Query) / I: 박서진·서우석(Dashboard), 윤지현(Backend&Infra)
- 전제 커밋: dadda5c (S4-5 login run 완료) 이후. 측정 definition_version: ATTACK 지표 뷰 그대로, M14 뷰 'ADR-S4-01 v2.0'.

## 맥락 (Gap #7)
S4-4 step0 실측에서 SQLi 앱 룰 100210이 Caldera error-based probe(`keyword='`, 단일 작은따옴표)를 탐지하지 못했다(APP_RULE 100210 = 0).
100210 정규식 `(?i)(union\s+select|pg_sleep|'\s*or\s*1=1|'[^']*--|information_schema)`은 작은따옴표 **단독** 주입을 잡지 못한다.
SQLi의 request-signal 탐지 폭을 넓혀(미탐↓) Miss Rate(M03 SQLI)가 유의하게 줄어드는지, 정상 검색 오탐(M14a)이 늘지 않는지를
한 변수(앱 룰 1개 추가)로 Before/After 측정한다.

## 변경 (한 변수)
- 앱 룰 **100211 추가 — DET0080 요청 신호 확장(AN0219/0220 Suspicious Command/Process Patterns)**. 100210 원문은 보존(이력·기존 경로 유지).
- 100211은 `http_request.*`만 본다(B안: 정답지 `validation.*`·응답 필드 미사용). SQL 주입 구문 신호 집합(따옴표·주석·문장구분·불린 주입·UNION SELECT·시간 지연 함수).
- 공격 ability·adversary, Suricata 룰(1000013 포함), target-web 코드, Correlation/Verdict 엔진, V1~V9는 **불변**. → Before/After 차이는 앱 룰 1개뿐.

### 설계 기록 — "요청→오류(5xx) 상관"을 쓰지 않은 이유 (A2 실측)
초안은 DET0080의 "요청→오류" 상관(요청 패턴 + 응답 5xx)을 쓰려 했으나 성립하지 않는다:
- `ProductController.search`는 SQL 오류가 나도 `statusCode`를 **200 고정**으로 두고 오류를 응답 **본문**(`{"error":…}`)에만 담는다(try/catch 양쪽 statusCode=200).
- `AttackLogger`는 attack.json.log의 `http_response`에 `{code, latency_ms, body_length}`만 기록(`code = exchange.statusCode()` = 200). 관제가 볼 수 있는 5xx·오류 문자열 신호가 없다.
- 오류 신호는 `validation.outcome`(정답지)에만 존재 → B안상 룰 조건에 쓸 수 없다.
- 앱이 5xx를 내도록 고치는 것은 **측정 대상(target-web) 변경**이라 이번 사례 밖(다음 후보). 따라서 100211은 요청 신호 확장으로 한정한다.

## Before / After
- Before = **S4-STACK-6-BASELINE**(ATTACK) + **S4-5-BENIGN-WEB-R2**(BENIGN), 이미 스냅샷된 `metric_snapshot` 행만 비교(라이브 뷰 아님).
- After = **S5-SQLI-AFTER**(ATTACK 20 op) + **S5-SQLI-AFTER-BENIGN-WEB**(같은 WEB 코퍼스 960건). After BENIGN은 After ATTACK과 같은 `rules_digest`로 M14b 짝이 성립.
- 비교는 `compare_snapshots(before_run, after_run)`(V10)로 metric·scope별 Newcombe 95% 차이 구간. `definition_version`이 다르면 비교 거부(RAISE).

## 판정 (주지표 + 가드레일, 사전 선언)
- **주지표**: SQLi Miss Rate M03(scope SCENARIO, split SQLI)의 Newcombe 95%(After − Before) **상한 < 0 → PASS**(미탐 유의 감소).
- **가드레일1**: M14a APP_RULE 엔드포인트별(search·download·preview) FPR Newcombe 95% **하한 > 0 이면 FAIL**(정상 오탐 유의 증가). 룰로 회피하지 않고 측정한다.
- **가드레일2**: After ATTACK의 PT·BF·SSRF verdict 분포·CONTROL·공격자 일치율(M09) 게이트가 Before와 동일(SQLi 외 시나리오 불변).
- **가드레일3**: 두 run R10 VALID, `rules_digest` 변경(vuln_rules.xml 포함, A4), 그 외 스택 digest(Suricata·Caldera·이미지)는 동일(증거 로그에 기록).

## 알려진 위험 (사전 명시)
- 요청 신호 확장은 **따옴표 포함 정상 검색어 오탐**을 늘릴 수 있다(예: O'Reilly, it's). 이는 룰로 피하지 않고 **가드레일1이 측정**한다
  (Summiting the Pyramid의 견고성↔정밀도 모순 — Gap #7의 원인과 같은 축). 100211이 정상어 따옴표에 발동해도 그 자체는 실패가 아니라 측정 대상이다.
- 단일 페이로드(작은따옴표 하나)에만 맞춘 룰이 아니라 SQL 주입 **행위**(구문 신호 집합)를 잡는다 — 과적합(가드레일 코퍼스 맞춤) 방지를 위해 홀드아웃(정상 코퍼스)은 룰 작성 중 열지 않았다.

## 하지 않는 것 (다음 후보)
- Suricata 1000013 수정, 페이로드 추가(sqli_union_extract 등), login NIDS 개선(별도 사례). target-web 5xx 반환화(앱 변경).

## 근거
- 계획서 H3(미탐 감소 가설), MITRE ATT&CK Evaluations — Configuration Change(Detection Logic), DET0080/AN0219·AN0220(Suspicious Patterns, request content),
  Newcombe(1998) method 10(두 독립 비율 차의 square-and-add 신뢰구간, z=1.959964), Kohavi 외 — 가드레일·주지표 사전 선언, 토스 "주지표 1 + 가드레일",
  Gartner AEV — 방어 최적화(룰·커버리지 검증). B안(관제 독립): 룰은 http_request 신호만 본다.

## 개정
- v1.1 (2026-10-22, 측정 전): 100211 신호에서 bare 주석 토큰(-- # /*)과 lookbehind 제외.
  이유 ① 검색은 '%keyword%' 문자열 문맥이라 주석·불린 주입도 따옴표로 문자열을 깨야 성립 → 따옴표 신호로 커버
  ② bare 토큰은 정상어(laptop--pro) 오탐 유발 ③ lookbehind의 XML 이스케이프(&lt;)가 Wazuh pcre2 필드에서 로드 실패를 일으킴
  — 운영 배포 전 임시 manager logtest(B3)에서 발견(CRITICAL: Error loading the rules).
