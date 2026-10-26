# ADR-S4-01: 검증 지표 정의서 (Metric Definitions v1)

- 상태: Accepted (2026-10-18)
- 개정 v1.1 (2026-10-18): S4-1 Step 0에서 verdict 분포 조회 후 정의 모호성 발견(대조군 요청이 공격 verdict로 집계).
  R10 유효성은 선택지와 무관하나, 대조군 제외로 SSRF 지표가 유리해지므로
  과거 run의 게이트·결론은 재분류로 바꾸지 않고 재측정으로만 판정한다(M09 비고).
- 개정 v1.2 (2026-10-18): S4-2 착수 전, 어떤 지표 값도 산출하기 전 개정. 계산 세부(백분위·Wilson 경계·R10 상태·범위 목록)를 고정.
- 개정 v1.3 (2026-10-19): V4 구현 전, 지표 데이터 조회 전 개정(현성 DRI 2026-10-19).
  D1 ALL 범위·분할 행 표시, D2 M06b 분자, D3 M09 뷰의 성격을 고정. 불변식 I5·I6 추가.
- 개정 v1.4 (2026-10-19): V4 red 검토에서 나온 정의 명확화, 지표 데이터 조회 전(현성 DRI 2026-10-19).
  D4 R5 보조값 initial 기준, D5 M08 기법 분할, D6 UNKNOWN 단위 매핑, D7 지표 대상 run 필터. 읽기 전용 role 권한 메모.
- 개정 v1.5 (2026-10-20): ATT&CK 매핑 기준 버전 명시 — Enterprise v20.0(2026-10-13). 19.2→20.0 공식 변경 목록에서
  T1190·T1110(하위 포함)·DET0080·DET0463·AN0219~0225·AN1275~1277 변경 없음 확인. 데이터 컴포넌트
  Application Log Content(v3.1)·Network Traffic Content(v2.2) 마이너 변경은 기법·탐지 전략·분석이 그대로라 매핑 무영향.
  DACI C(오정현)·push 전 오정현 리뷰 규칙(헤더 DRI 줄의 C, 결과(Consequences)의 push 전 리뷰 규칙)은 ADR-S4-02 D7로 대체(2026-10-20, 현성 DRI).
- 개정 v1.6 (2026-10-21): S4-3 착수 — R13 스냅샷 규칙 신설(라이브 뷰와 별개인 불변 기록 층 metric_snapshot·철회 기록). 기존 절 변경 없음, R7은 R13 d로 표현만 정밀화.
- 개정 v1.7 (2026-10-21): S4-4 착수 — R14 NIDS 입력, R15 M07a 정의 보강, R16 M13 통제 판정 신설(현성 DRI 2026-10-21 Q1~Q4 결정).
  기존 절 변경 없음. 지표 카드 M07a·M13 행과 I2는 R15·R16으로 구체화. 지표 뷰 definition_version은 'ADR-S4-01 v1.7'로 올린다(R14 e).
- 개정 v1.8 (2026-10-22): S4-5 착수, 정상 코퍼스 데이터를 보기 전 고정 — R17 BENIGN run, R18 M14a·M14b 산출 규칙 신설(현성 DRI 2026-10-22).
  기존 절 변경 없음. 지표 카드 M14a·M14b 행과 "정상 코퍼스(M14) 규칙"은 R17·R18로 구체화(run당 n ≥ 300 → 엔드포인트별 n ≥ 300으로 강화).
- 개정 v1.9 (2026-10-22): M14b 비적용 통제 상태를 M13·M14a와 같은 규칙으로 고정(R18 f') — 스냅샷 전 S4-5-BENIGN-WEB-R2 확인에서 발견, v1.8 스냅샷 0행. M14 뷰 definition_version 'ADR-S4-01 v1.9'(V8).
- 개정 v2.0 (2026-10-22): S4-5 login run(S4-5-BENIGN-LOGIN) — R17 f 외부 전송 BENIGN run, R18 j BACKEND_CORR·login NIDS 오탐 판정 신설(현성 DRI 2026-10-22).
  기존 절 변경 없음. login 전송은 사람이 실행(비밀번호 미보관, CWE-798·S0-A 원칙), 코드는 결과 CSV를 입력으로만 받는다. M14 뷰 definition_version 'ADR-S4-01 v2.0'(V9).
  V9는 benign_endpoint에 login 행(scenario=BRUTE_FORCE)을 추가하고 v_metric_m14a·m14b의 definition_version 상수만 v1.9→v2.0으로 올린다 — 뷰 로직·컬럼·분모는 완전 불변(V8이 v1.8→v1.9 한 것과 같은 성격).
- DRI: 이현성 / C: 오정현(Schema·Metrics Query) / I: 박서진·서우석(Dashboard), 윤지현(Backend&Infra)
- 기준 커밋: dc66322 (S3 종료, 20회 게이트 SQLi·PT·BF PASS / SSRF FAIL)

## 맥락
S3 종료 시점 verdict_result 160행이 적재돼 있으나 run 차원이 없다. S4 지표 데이터를 보기 전에
지표 정의·불확실성 표기·목표 판정 계산법·S5 비교 규칙·측정 신뢰 검사를 고정한다.

## 근거 (등급: 1차=원문 확인 / 2차=해석 글 교차 / 해석=우리 적용)
- (1차) MITRE ATT&CK Evaluations Detection Categories: 서브스텝별 최고 맥락 카테고리 1개,
  Configuration Change·Delayed 분리 표기, Delayed는 정상 수집·처리 지연에 미적용
- (2차) MITRE Evals 집계: Telemetry/Analytic Coverage·Visibility 정의(벤더 해설 교차 일치)
- (1차) Agresti & Coull(1998), Brown·Cai·DasGupta(2001): 소표본 비율은 Wilson 구간(n≤40 권고)
- (1차) Microsoft Sentinel·Elastic 문서: 조회 윈도 ≥ 소스별 실측 수집 지연(고정 배수 규칙 없음)
- (1차, 출판사 요약) Kohavi·Tang·Xu(2020): 가드레일 사전 선언, SRM 신뢰 가드레일은 모든 실험에 포함
- (1차) NIST SP 800-55 Vol.1·2(2024-12): 측정치 문서화·데이터 품질·불확실성
- (1차) DeTT&CT: 가시성과 탐지 분리
- 내부: 결정 1~4(계획서 v3), S0 측정 결론, S0 실측 IDS 전용·AR 비활성, 토스 실험 원칙
- Hyndman & Fan(1996) American Statistician 50:361–365: 표본 분위수 9종 중 type 8 권고(type 7은 R·PostgreSQL 기본값 관행)
- Fabijan 외(KDD 2019), Microsoft ExP: 모든 실험은 효과 분석 전 SRM 검사 통과, 원인은 파이프라인 단계별로 진단
- Dmitriev 외(KDD 2017): 비율 지표는 분자·분모 카운트 병기, 조기 중단은 흔한 실수

## 공통 규칙
- R1 원천: 판정은 verdict_result.verdict 단일 원천. M05·M13만 verdict_member·detection_link 조인 허용. 판정 재계산 금지.
- R2 분모: UNCERTAIN은 모든 비율 분모에서 제외. 예외 M05·M07a·M08(신뢰도·가시성 자체를 재는 지표).
- R3 불확실성: 모든 비율은 분자/분모와 Wilson 95% 구간 함께 표기. 평균 단독 표기 금지.
  Wilson 95% 구간은 z = 1.959964(양측)로 계산한다. 분자·분모 카운트를 항상 함께 표기한다.
  n = 0이면 점추정·구간을 NULL로 두고 "해당 없음(n=0)"으로 표기한다(0%·[0,1] 표기 금지, R8과 같은 원칙).
- R4 범위: run 단위 계산, run 간 합산 금지.
- R5 늦은 탐지: 최종 verdict 기준으로 탐지에 포함(MITRE Delayed와 동일), M10으로 별도 표기. initialVerdict 기준 값은 보조로 병기.
  보조값(M02_INITIAL·M03_INITIAL)은 분자·분모 모두 initial_verdict 기준이다(D4).
- R6 집계 단위: Verdict 1건 = 공격 시도 1건(BF = 시퀀스, 스프레이 = IP 캠페인 1건).
  공격 ability 내 대조군(control) 요청은 공격 시도가 아니다. attempt_role=CONTROL로 분류하고
  공격 지표(M01~M10·M13) 분모에서 제외, 별도 보고한다(MITRE technique-under-test 원칙).
- R7 정의 변경: ADR 개정 + metric_snapshot.definition_version 증가. 기존 스냅샷 재계산 금지.
  R13 d로 표현 정밀화(v1.6).
- R8 Block Rate: N/A(0%로 표기 금지).
- R9 비교(S5 사전 고정): run 간 비율 차이는 Newcombe 95% 구간으로 판정.
  H3 성공 = Miss Rate(After−Before) 구간 상한 < 0. 가드레일 M08·M14a는 차이 구간 하한 > 0이면 악화(차단).
  조건 불충족 시 INCONCLUSIVE(사후 기준 변경 금지).
  After run의 탐지는 MITRE "Configuration Change-Detection Logic"에 해당하므로 rules_digest 차이로 Before와 구분 표기.
- R10 표본 무결성(SRM 대응): expected_attempts = Σ(ability별 공격 시도 단위) × operation 수,
  expected_controls = Σ(ability별 대조 요청 수) × operation 수. 실제 ATTACK·CONTROL 건수가 둘 다 일치해야 VALID,
  아니면 INVALID(지표 미산출, 원인 기록).
  run 상태는 3종이다. VALID = CLOSED이고 ATTACK·CONTROL 실제 건수가 기대 수와 모두 일치.
  INVALID = CLOSED이지만 불일치하거나 기대 수가 없음(원인 기록). INCOMPLETE = OPEN(미완료, 중단 포함).
  지표는 VALID run에서만 산출한다. 모든 verdict는 하나의 run에 귀속된다(run_id NOT NULL).
- R11 백분위: 모든 백분위(M04 p50·p95, M11a·M11b p50·p95·p99)는 Hyndman & Fan(1996) type 8로 계산하고 n을 병기한다.
  n = 0이면 NULL·"해당 없음(n=0)". 재현 검증 기준: R quantile(type=8), NumPy method='median_unbiased'.
- R12 범위 단위: M06a·M06b의 분모는 데이터가 아닌 고정 범위 목록에서 가져온다.
  기법 = {T1190, T1110} (ATT&CK Enterprise v20.0), 시나리오 = {SQLI, PATH_TRAVERSAL, BRUTE_FORCE, SSRF}.
  시도가 0건인 단위도 분모에 포함한다. 목록 변경은 ADR 개정(R7)으로만 한다.
- R13 스냅샷 규칙(v1.6): 지표 뷰(V4)는 볼 때마다 현재 정의로 다시 계산하는 라이브 층이고,
  metric_snapshot은 측정 시점 값을 복사·고정하는 기록 층이다(S5 Before/After 비교의 원천).
  - a 대상: R10 VALID run만. INVALID·INCOMPLETE는 사유 메시지(R10 상태)와 함께 거부한다.
  - b 형식: 1행 = 관측 1개 = (run_id, definition_version, metric_id, scope_kind, scope_key).
    S4-2 범위 지표 뷰 결과 전부를 담는다(시나리오 UNKNOWN 행 포함).
  - c 값: 분자·분모를 항상 저장한다. 비율은 점추정 + Wilson 95% 하한·상한. n = 0이면 점추정·구간 NULL("해당 없음").
    MTTD는 p50·p95(type 8) + n. status는 원 뷰 값 그대로 복사한다(변환 금지 — M12 NOT_APPLICABLE, M05 H2는 h2_status).
    M09 criteria_met은 boolean 컬럼 criteria_met에 그대로 둔다.
  - d 불변: 기존 스냅샷 덮어쓰기·삭제 금지(UPDATE·DELETE·TRUNCATE 거부, 트리거 + 권한).
    같은 run + definition_version 중복은 거부한다. 정의가 바뀌면 새 definition_version 행으로 추가한다.
    라이브 뷰(현재 정의로 재계산)와 스냅샷(측정 시점 고정)은 별개 층이다.
    한계: 테이블 소유자는 ALTER TABLE로 사용자 트리거를 끌 수 있다(PostgreSQL 16 문서).
    validation 스키마 소유자가 validation_rw이므로(S4-3 Step 0) 불변 보장은 일반 DML에 한정된다 —
    detections/known-gaps.md에 기록, role 분리는 별도 슬라이스 후보.
    스냅샷이 있는 run은 삭제 불가(FK ON DELETE RESTRICT), 스냅샷이 없는 run은 삭제 가능.
    FK 확인 쿼리(FOR KEY SHARE)는 참조 테이블 소유자 권한으로 실행되고(1차급: postgresql.org 메일링리스트 Tom Lane 답변 — FK 확인은 테이블 소유자 권한으로 실행, 문서 본문 명시 없음 + 실측)
    잠금 절은 최소 한 컬럼의 UPDATE 권한이 필요하므로(PostgreSQL 16 SELECT 문서) run_id 컬럼 UPDATE만 허용, 실제 수정은 트리거가 차단.
  - d' 철회: 잘못된 스냅샷은 DELETE 대신 metric_snapshot_withdrawal(append-only)에 사유를 기록한다. 원 행은 그대로 둔다.
  - e 출처: definition_version = 원 지표 뷰들의 definition_version 값(현재 'ADR-S4-01 v1.4')을 자동 사용, 뷰마다 다르면 거부.
    snapshot_rule_version = 'ADR-S4-01 v1.6'(상수), schema_version(스냅샷 시점 Flyway 최신), run의 git commit·git_dirty·rules_digest 복사, snapshot_at.
  - f 표기: 보고서·발표·대시보드의 비율은 "분자/분모 (점추정, Wilson 95% 하한)"으로 쓴다. 100% 단독 표기 금지.
    전부 성공일 때 하한 = n/(n+z²) (예: 20/20 → 83.9%, 140/140 → 97.3%).
  - g 조회: validation-api가 스냅샷을 읽을지 라이브 뷰를 읽을지는 S4-6 착수 때 확정한다(ADR-S4-02와 동일).
  - 근거(등급 표기 그대로):
    - 기업별 1차·직접: 토스 토션(toss.tech/article/tossion, 2026-08-11) — 테스트 런은 시점 값을 복사해 저장,
      Closed 시 스냅샷 고정, 원본 삭제와 무관하게 리포트 유지, 입력 수·결과 수 대조
    - 표준 1차: OSF registration(동결·수정·삭제 불가, 철회만 가능, 메타데이터 유지)
    - 표준 1차: Microsoft ExP(모든 A/B 테스트는 효과 분석 전 SRM 검사 통과)
    - 표준 1차(개요, 본문 미열람): NIST SP 800-55v1 2024(측정치 문서화·데이터 품질·불확실성)
    - 표준 2차(원문 유료): ISO/IEC 27001:2022 9.1(측정 결과 증거 보관·비교·재현 가능), 7.5.3(무결성 보호·변경 통제)
    - 표준 2차(학술): MITRE ATT&CK Evaluations 방법론 변경에 따른 라운드 간 불일치(arXiv 2401.15878)
    - 기술 1차: Wickham "Tidy Data" JSS 59(10) 2014(관측=행, 변수=열)
    - 기술 1차: PostgreSQL 16 CREATE TRIGGER(TRUNCATE는 문장 트리거만)·ALTER TABLE(소유자만, 사용자 트리거 비활성화 가능)
    - 기술 1차: Kohavi·Tang·Xu 8장 Institutional Memory(모든 실험·변경 이력)
    - 기술 1차: Optimizely 문서(비율 지표는 분자·분모를 함께)
    - 2026 1차: Gartner 2026 Digital Provenance(2025-10-20 보도자료, 데이터·프로세스의 출처·무결성 검증)
    - 반대 사례: Airbnb Minerva(정의 변경 시 backfill 재계산) → 라이브 층/기록 층 두 층 구조로 해소
- R14 NIDS 입력(v1.7): Suricata 알림을 시도에 연결해 탐지·verdict·M13에 반영한다.
  - a 알림 원천: 인덱서 wazuh-alerts-*의 rule.id = 86601(Suricata alert). alertTime = Wazuh timestamp(결정4와 동일).
    기존 vuln-webapp 그룹 질의는 그대로 두고 별도 질의로 읽는다(86601은 vuln-webapp 그룹이 아니다 — groups [ids, suricata]).
  - b 알림↔http: Wazuh data.(flow_id, tx_id) ↔ eve.json http 이벤트 (flow_id, tx_id).
    실측: S4-STACK-6-BASELINE 구간 Wazuh 86601 2022건 중 2022건 연결, URL 일치 2022(2026-10-21 design-check 로그 C2).
    Wazuh는 data.flow_id를 실수 문자열('578501012733101.000000')로 저장한다 — 소수부가 0이 아니면 연결하지 않는다.
    eve http와 연결되지 않은 86601 알림(orphan)은 run별로 수를 기록한다(nids_window_stat).
  - c http↔시도: UA(Caldera/<paw>/<technique>/<ability_id>)의 paw·ability_id가 시도(앱 이벤트)와 같고,
    http 시각과 시도 시각이 같은 Caldera 링크 창(OperationResolver와 같은 창: 링크 [decide, finish+1s])에 들고,
    URL이 일치하는 시도. URL 비교: path는 그대로 비교, eve query는 정확히 1회 URL 디코딩(서버와 같은 1회) 후 앱 http_request.args와 비교.
    eve url에 query가 없으면(BF POST — body는 eve에 없음) path + 링크 창 + ability만 본다.
    후보가 여럿이면 시각 최근접 1건, 후보 0이면 연결하지 않는다.
    match_path = UA_FALLBACK, confidence 0.7(결정3 — 판정 사용 가능 하한). detection_link.control = NIDS.
    링크의 technique은 연결된 시도의 technique_id(86601에는 technique 필드가 없다), rule_id는 signature_id.
  - d sid 분류(아래 "v1.7 NIDS sid 분류표"): ANALYTIC만 탐지·verdict·M13에 반영한다.
    MARKER(Caldera UA·X-Caldera 헤더)는 technique-under-test가 아니고(MITRE Evals), B안(탐지는 테스트 표식과 독립)에 따라 제외한다.
    TELEMETRY(엔드포인트 요청 자체 매칭)는 링크로 쓰지 않고 수만 기록한다(nids_window_stat). UNDECIDED(판단 보류)·분류표 밖 sid도 링크 제외.
  - e 파이프라인 변경 표기: R14 이후 run은 MITRE "Configuration Change – Data Sources"에 해당한다.
    S4-STACK-6-BASELINE 스냅샷(definition_version 'ADR-S4-01 v1.4')은 이력으로 두고, S5 Before는 S4-7 이후 새 baseline(20회)이다.
    지표 뷰 definition_version은 'ADR-S4-01 v1.7'로 올린다(식은 v1.4와 같다 — 입력 링크에 NIDS가 더해지는 변경, R7).
    NIDS 링크가 판정에 들어가므로 SQLi·PT·SSRF의 MTTD(M04)는 R14 전 run과 비교 기준이 아니다(첫 탐지 통제와 함께 기록만).
    M05(링크 ≥1 시도의 best source 분포)의 분모에도 NIDS 링크만 있는 시도가 들어갈 수 있다.
- R15 M07a 정의 보강(v1.7): 분모 = 지표 대상 ATTACK 시도 전부(UNCERTAIN 포함, R2 예외). 분할 = 전체·시나리오.
  - 센서 APP_LOG: 시도 원천이 앱 로그이므로 VALID run(R10)에서 구조적으로 1이다. 값은 기록하되 해석 지표가 아니다.
  - 센서 NIDS: 시도에 연결된(R14 c) eve http 이벤트 ≥ 1인 시도 / 전체 시도.
  - 저장: telemetry_observation(verdict 1건 × 센서 = 1행, event_count). R14 이전 run은 수집하지 않았으므로
    status 'NOT_COLLECTED'(분자·점추정 NULL — 0% 표기 금지, R3·R8과 같은 원칙). 수집 여부 = run의 nids_window_stat 행 존재.
- R16 M13 통제 판정(v1.7): 분모 = 시나리오의 S_ALL(M02 분모, 지표 카드 M13). 분할 = 통제 × 시나리오(범위 4종).
  통제 목록은 metric_scope kind = CONTROL(APP_RULE·NIDS·BACKEND_CORR) 고정 목록이다(R12와 같은 방식).
  - APP_RULE: control = APP_RULE 링크 중 conf ≥ 0.7 ∧ technique = 시도 technique(VerdictEngine 단건 기준과 같은 조건). SQLi·PT·SSRF.
  - NIDS: control = NIDS 링크 중 conf ≥ 0.7 ∧ technique 일치 ∧ ANALYTIC sid. 4종 중 ANALYTIC sid가 있는 시나리오만, 없으면 'NO_RULE'.
  - BACKEND_CORR: verdict_result의 BF 판정 성립(BF 단위의 detection_status = DETECTED — AN1275 시퀀스·AN1277 스프레이). BF만.
    100231·100233은 보조 기록이며 M13 분모·분자에 넣지 않는다.
  - 상태: 룰 없음 = 'NO_RULE', 통제 정의상 대상 아님(APP_RULE × BF) = 'NOT_APPLICABLE', R14 이전 run의 NIDS = 'NOT_COLLECTED',
    n = 0 = 'NO_DATA'. 앞의 셋은 분자·점추정 NULL(0% 표기 금지).
  - I2 시나리오별 구체화: SQLi·PT·SSRF = (APP_RULE ∪ NIDS) ⇔ DETECTED, BF = BACKEND_CORR ⇔ DETECTED
    (각 시나리오의 합집합 x = M02 분자, SUCCEEDED_BLOCKED는 현 파이프라인에서 도달 불가).
    BF 판정은 BACKEND_CORR만 쓴다(VerdictEngine 판정 규칙 불변). NIDS × BF는 M13 보조 보고이며 I2에 넣지 않는다 — S5 이후 검토 후보.
  - VerdictEngine compromise(AN1276) 판단은 100232 또는 100233. Wazuh는 같은 이벤트에서 하위 룰 100233을 우선해 100232가 나지 않는다
    (실측 S4-STACK-6-BASELINE: 100232 = 0, 100233 = 20). 다른 판정 규칙은 그대로.
  - 스냅샷(R13): M07a는 metric_id M07a_APP_LOG·M07a_NIDS(전체·시나리오), M13은 M13_<통제>(시나리오). status는 뷰 값 그대로.
- R14~R16 근거(등급 표기 그대로, 현성 DRI 2026-10-21):
  - 1차(attackevals.mitre-engenuity.org 원문): MITRE ATT&CK Evaluations Detection Categories — technique-under-test, Configuration Change, Delayed
  - 2차(벤더 해설 교차 일치, MITRE 결과 페이지 원문 미열람): Telemetry/Analytic Coverage 집계 정의
  - 1차(Rabobank DeTT&CT 위키): 가시성·탐지 분리
  - 1차(attack.mitre.org): DET0080 / AN0220 — NSM:Flow·HTTP 페이로드 관측
  - 1차(실측): Suricata eve flow_id·tx_id — 2026-10-21 step0 로그 0-4, design-check 로그 C2
  - 2차(보안뉴스 보도, 업체 자기 설명): SK쉴더스 EQST 관제 연계 검증 — 관제가 스스로 탐지 → SIEM 경로
  - 1차(gartner.com Peer Insights 시장 정의): Gartner AEV(Adversarial Exposure Validation) 정의
  - 2차(벤더 요약, Market Guide 원문 유료): AEV 방어 최적화 사용사례(SIEM 룰·ATT&CK 커버리지 검증)
- R17 BENIGN run(v1.8): 정상 요청만 보내는 run. measurement_run.kind = BENIGN.
  - a 전송: Caldera를 쓰지 않고 Caldera 헤더(X-Caldera-*)·Caldera UA 없이 일반 브라우저형 UA로 보낸다(정상 사용자 모사).
    정상 라벨은 코퍼스 manifest에만 둔다(B안). validation.outcome은 M14에서 쓰지 않는다.
  - b 사전 조건: Caldera running/paused operation 0개, sandcat agent 꺼짐 — 측정 창 안 Caldera 헤더 없는 앱 로그 = 코퍼스 요청만.
  - c 대조: target-web 응답에는 rid가 없다(S4-5 C1). 앱 로그(attack.json.log, Caldera 헤더 없는 줄)와 코퍼스를
    전송 순서 + path + args + 전송~응답 시각 창으로 1:1 대조하고, 대조된 줄의 rid를 그 요청의 rid로 쓴다.
  - d R10 BENIGN 분기: expected_attempts = 코퍼스 요청 수. VALID ⇔ CLOSED ∧ 기대 요청 수 = benign_request 적재 수 = 앱 로그 대조 성공 수.
    불일치는 INVALID(원인 기록: BENIGN_LOAD_MISMATCH·BENIGN_MATCH_MISMATCH), 기대 수 없음은 INVALID(EXPECTED_MISSING), OPEN = INCOMPLETE.
    ATTACK run의 R10 판정은 그대로다.
  - e run 구성: S4-5는 BENIGN run 2개로 나눈다. S4-5-BENIGN-WEB(search·download·preview, 하네스 자동 전송)과
    login run(S4-5 범위 안, 별도 작업). R10은 run마다 따로 판정한다.
    S4-5 완료 조건 = WEB run과 login run 둘 다 R10 VALID이고 스냅샷이 있다.
  - f 외부 전송 BENIGN run(login, v2.0): 전송을 코드가 하지 않고 사람이 터미널에서 실행한 뒤, 전송 기록 CSV(seq,sent_at_ms,responded_at_ms,status)를
    입력으로 받아 대조·적재한다. 비밀번호는 코퍼스·코드·로그·DB 어디에도 두지 않는다(계정 별칭만 manifest). 근거: 자격 증명을 측정 도구에 두지 않음(CWE-798,
    NIST AC-5·AC-6, Gartner 2026 AI 에이전트 IAM), 전송 자체는 재현 가능한 스크립트로 저장(Gartner AEV "자동화·재현"). 이 분리는 login 전용 산출물이
    AI 코딩 도구 안전필터에 반복 차단되어 재검토한 결과이며, 위 표준과 일치해 채택. 대조 창·단일 후보 조건은 WEB run과 같다(ExternalSendIngest §I:
    다음 sent_at − 이전 responded_at > 2×TOLERANCE, 위반 시 적재 전 실패·사유 기록·run OPEN 유지). 통제 적용은 benign_endpoint 설정(scenario)만 따른다.
- R18 M14 산출(v1.8):
  - a M14a FPR: 단위 = 정상 요청 1건 × 통제. FP ⇔ 그 요청에 연결된, 그 통제의 판정용 알림 ≥ 1, 아니면 TN.
    분모 = 그 엔드포인트의 대조된 정상 요청 수. 분할 = 통제 × 엔드포인트(엔드포인트는 시나리오에 대응 — search=SQLI,
    download=PATH_TRAVERSAL, preview=SSRF, login=BRUTE_FORCE).
  - b 통제 적용 대상은 M13과 같다: APP_RULE = search·download·preview(login은 NOT_APPLICABLE), NIDS = ANALYTIC sid가 있는 엔드포인트
    (R14 d — TELEMETRY·MARKER·UNDECIDED·분류표 밖 sid는 기록만), BACKEND_CORR = login 시퀀스(그 밖은 NO_RULE).
  - c 연결: APP_RULE = Wazuh alert(vuln-webapp 그룹)의 data.rid = 대조된 rid(S4-5 C2).
    NIDS = Suricata alert(86601)의 data.http.url = 보낸 요청 대상(path+query 원문) ∧ alert의 eve 시각(data.timestamp)이
    그 요청의 전송~응답 시각 창 안 ∧ Wazuh alert 시각 ≤ 응답 + 관찰 30s(결정4). 순차 전송이라 후보는 1개여야 하고,
    0개·2개 이상이면 연결하지 않고 미연결로 기록한다.
  - d 표본: 엔드포인트별 n ≥ 300 (FP 0건이면 Wilson 95% 상한 = z²/(n+z²) ≈ 1.26%, n = 300).
  - e M14b FDR: FP 알림 / (FP 알림 + TP 알림), 통제별. FP 알림 = BENIGN run에서 정상 요청에 연결된 판정용 알림 수.
    TP 알림 = 짝 ATTACK run의 판정용 링크 수(APP_RULE·NIDS = 그 통제의 conf ≥ 0.7 링크, NIDS는 ANALYTIC sid만,
    BACKEND_CORR = BF 판정이 성립한 단위의 링크). 짝 run = rules_digest가 같은 VALID ATTACK run 중 스냅샷이 있는 가장 최근 run
    (2026-10-22 기준 S4-STACK-6-BASELINE — S4-5 C3 rules_digest 일치). 짝이 없으면 'NO_PAIR'(해당 없음 — 짝 run 없음).
    짝 run이 NIDS를 수집하지 않았으면(R15, nids_window_stat 없음) NIDS는 'NOT_COLLECTED'.
  - f 상태: 통제 대상 아님 = 'NOT_APPLICABLE', 룰 없음 = 'NO_RULE', n = 0 = 'NO_DATA'(점추정·구간 NULL, 0% 표기 금지).
    적용 통제의 판정 행 수가 대조된 요청 수와 다르면 'RESULT_MISMATCH'(값 NULL — 조용한 과소 집계 방지).
  - f' (v1.9) 비적용 통제 상태는 M13·M14a·M14b가 같다: M14b는 그 통제의 M14a 칸이 모두 비적용이면 그 칸 상태(NO_RULE 우선)를 쓴다 — BACKEND_CORR × 웹 엔드포인트 = NO_RULE(R18 b·R16).
    엔드포인트에 해당 BENIGN run이 아직 없으면 행이 없다 = "해당 없음(run 없음)" — login 칸은 login run 전까지 이 상태다.
  - g 기록만(판정 제외): 룰 ID별 알림 수, 측정 창 안 미연결 알림(APP_RULE rid 불일치, NIDS 후보 0·2개 이상).
    NIDS 배경 이벤트(src·dest가 fe80::/10·ff00::/8)는 미연결 기록에서도 제외한다.
  - h 스냅샷(R13): BENIGN VALID run은 M14a(metric_id M14a_<통제>, scope SCENARIO = 엔드포인트의 시나리오)와
    M14b(M14b_<통제>, scope ALL, paired_run_id = 짝 run)를 저장한다. M14 뷰의 definition_version = 'ADR-S4-01 v1.8'.
    BENIGN 스냅샷의 snapshot_rule_version = 'ADR-S4-01 v1.8'. ATTACK run 스냅샷 경로·상수('ADR-S4-01 v1.6')는 그대로다.
  - i 환경 제약: 운영 업로드 폴더가 비어 있어 정상 다운로드는 404, preview는 외부 연결 결과에 따라 응답이 달라진다
    (target-web 외부 fetch: 연결 3s·응답 3s 타임아웃, 리다이렉트 안 따라감). 룰이 응답 코드·본문을 조건으로 쓰는지는 아래 "v1.8 환경 제약 확인"에 기록.
  - j (v2.0) login 오탐 판정: BACKEND_CORR·NIDS는 정상 로그인 요청에 상관 탐지 alert가 링크되면 FP다.
    · BACKEND_CORR: login 요청 rid에 100231(실패 10회/120초) 또는 100233(반복 실패 후 성공)이 링크되면 FP. 100230(실패 단건)·100232(성공 단건)은
      recorded(기록만, R18 g) — 정상 로그인에도 뜨는 단건 신호라 상관 통제 FP가 아니다. 판정은 Wazuh 상관 룰의 alert 유무로 하며(B안: 관제 독립),
      CorrelationEngine·VerdictEngine을 쓰지 않는다 — gtOutcome(정답지)은 M14 어디에도 들어가지 않는다(R17 a 유지). 100231/100233은 시퀀스 성립 시
      1회 뜨는 상관 룰이라 집계 단위가 자연히 시퀀스다(R6·R16과 정합). 정상 코퍼스에선 시퀀스가 성립하지 않아야 정상(FP 0 기대).
      연결은 APP_RULE과 같은 rid 대조다: 100230~100233 alert는 data.rid를 싣고(S4-4 step0 실측 — ATTACK run에서 100231·100233 match_path RID 20/20),
      그 rid를 대조된 요청 rid와 맞춘다(시각창 아님).
    · NIDS: login 요청에 ANALYTIC sid(1000031·1000032)가 링크되면 FP. 모든 login 요청의 url이 같으므로(/api/auth/login) url+시각 창으로 단일 후보를 정한다(R18 c).
    · login 상관 alert(100230~100233)는 룰 묶음 group name "vuln-webapp,attack-http-activity,"에 속해(vuln_rules.xml) rule.groups에 vuln-webapp가 붙는다 →
      기존 BENIGN 앱 alert reader(vuln-webapp 질의)가 그대로 읽는다(S4-4 step0 실측: 100230=220·100231=20·100233=20 전부 in_group_vuln-webapp). reader 확장 불필요.
    · 측정 조건: 단일 출발지 IP(127.0.0.1), 계정 순환, 전송 간격은 NIDS 단일 후보 조건으로만 결정(BF 임계치와 무관). 단일 IP·압축 시간은 실제 NAT 환경보다
      밀도가 높은 보수적 조건이라 FP는 과대 쪽으로 나온다. AN1277(스프레이)은 정상 계정 수 < 임계(5)라 이 코퍼스로 도달 불가 → "측정 범위 밖(코퍼스 계정 수 부족)"으로 표기(0으로 쓰지 않음).
    · 오타 케이스: 정상 사용자도 오타를 낸다(근거 Chatterjee et al. S&P 2016 MTurk 데스크톱 오타율 약 4.5% — 옮겨치기 조건이라 실제보다 높을 수 있음, 참고 Keith 2.2%).
      코퍼스의 TYPO 행은 실행 시점에 정상 비밀번호를 결정적으로 변형해 생성하고 파일·로그·DB에 남기지 않는다. 오타 1~2회는 임계 10에 못 미쳐 상관 FP가 아니어야 정상.

## v1.3 결정 (D1~D3, 현성 DRI 2026-10-19)
- D1 ALL 범위: ALL = run의 ATTACK 시도 전부(UNKNOWN 시나리오·기법 포함).
  분할 행 중 범위 6단위(R12 목록)는 n = 0이어도 항상 표시한다(NO_DATA, R3).
  UNKNOWN 행(시나리오·기법)은 해당 run에 그 단위 시도가 1건 이상일 때만 표시한다.
  불변식 I6: Σ 시나리오 n(UNKNOWN 포함) = ALL n, 기법도 동일.
  근거: (1차) MITRE ATT&CK Evaluations — 모든 서브스텝에 카테고리를 부여(None 포함, 누락 없음),
  (1차) Dmitriev 외(KDD 2017) — 분자·분모 병기.
- D2 M06b 분자: S_ALL ≥ 1 AND SUCCEEDED_MISSED = 0 인 범위 단위 수. 실행(성공) 0건 단위는 "일관 탐지"가 아니다.
  불변식 I5: M06b ≤ M06a.
  근거: (1차) MITRE — 탐지는 실행된 technique-under-test에 적용될 때만 인정.
- D3 M09 뷰의 성격: M09 뷰는 측정값(criteria_met)이며 결정3 게이트 전환 판정의 기록이 아니다.
  전환 판정은 v1.1 규칙대로 새 run에서만 한다. S3-GATE-dc66322의 공식 결과(SSRF FAIL)는
  게이트 리포트 증거가 원천이며, 뷰 값으로 바꾸지 않는다.

## v1.4 명확화 (D4~D7, 현성 DRI 2026-10-19 — V4 red 검토, 지표 데이터 조회 전)
- D4 R5 보조값: M02_INITIAL = (SUCCEEDED_DETECTED + SUCCEEDED_BLOCKED)_initial / S_ALL_INITIAL,
  M03_INITIAL = SUCCEEDED_MISSED_initial / S_ALL_INITIAL. S_ALL_INITIAL은 initial_verdict 기준 S_ALL.
  최종·initial 혼합 금지 — 혼합하면 initial MISSED → 최종 UNCERTAIN 시도가 분자에만 들어가 x > n이 될 수 있다.
- D5 M08 분할에 TECHNIQUE 추가(전체·시나리오·기법). I6 검증 기준은 M08이다(분모가 전체 시도인 유일한 지표).
- D6 단위 매핑: scenario·technique_id가 NULL이거나 metric_scope(R12)에 없으면 UNKNOWN 1행으로 집계한다.
- D7 지표 대상 run: measurement_run.kind = 'ATTACK' ∧ attempt_role = 'ATTACK' ∧ r10_status = 'VALID'.
  BENIGN run은 M14 전용이다.
- 메모: 읽기 전용 role(S4-6)에는 wilson_ci·quantile_t8 EXECUTE 권한을 별도로 부여해야 한다
  (V3에서 PUBLIC 회수, 뷰 안 함수 호출은 호출자 권한으로 검사).

## v1.7 NIDS sid 분류표 (R14 d, docker/config/suricata/local.rules 원문 기준, 현성 DRI 2026-10-21)
| 분류 | 시나리오 | sid | 근거(룰 원문) |
|---|---|---|---|
| MARKER | — | 1000001 | http.user_agent startswith "Caldera/" |
| MARKER | — | 1000002·1000003·1000004 | http.request_header "X-Caldera-Op-Id"·"X-Caldera-Technique"·"X-Caldera-Ability" |
| TELEMETRY | BRUTE_FORCE | 1000030 | POST /api/auth/login 요청 자체(패턴·임계치 없음 — 정상 로그인에도 걸림) |
| ANALYTIC | BRUTE_FORCE | 1000031·1000032 | threshold by_src 10/60s · 5/180s |
| ANALYTIC | SQLI | 1000010~1000017, 1000019 | UNION SELECT, ORDER BY(%20·+ --), /api/products/search %27, pg_sleep, ' … --, OR 1=1, tab UNION SELECT, CHR( |
| ANALYTIC | PATH_TRAVERSAL | 1000020~1000029, 1000040 | ../../, %2e%2e%2f, etc%2Fpasswd·etc%2Fshadow, usr%2Fbin, ..\, %u002e, %00, %c0%ae, ..././, .ssh id_rsa |
| ANALYTIC | SSRF | 1000060~1000069, 1000087 | 169.254.169.254, url= 127.0.0.1·localhost·10.x·192.168.x, metadata.google.internal, [::1], 2130706433, 0x7f, 위험 scheme, 127.x 단축 |
| UNDECIDED | SQLI | 1000018 | 중복 keyword= 파라미터(HPP) — 정상 요청에서도 생길 수 있어 공격 패턴 여부 판단 보류 |
| UNDECIDED | PATH_TRAVERSAL | 1000041 | download 경로에 "config" 문자열만 — 정상 파일명에도 걸릴 수 있어 판단 보류 |

분류표 밖 sid(XSS 1000050~58, CMDI 1000070~79·1000170~174)는 4종 시나리오의 시도가 아니므로 링크 제외. 분류 변경은 ADR 개정 + 새 마이그레이션으로만 한다.

## v1.8 환경 제약 확인 (R18 i, 코퍼스 해시 고정 뒤 룰 읽기 — 2026-10-22 s4-5-impl 로그 B3)
- 코퍼스: detections/corpus/benign/benign-corpus-v1.yaml (sha256 b73caa5fb6d0bb6e9818b01716480e5fd6009fdedf4da9ea3044854f4e7ca76c),
  search·download·preview 각 320건. 컨트롤러 기능 명세만으로 생성(gen_benign_corpus_v1.py), 생성 중 탐지 룰·negative-test 정의 미열람.
  한계: 작성자(Claude)는 S4-4에서 local.rules·vuln_rules.xml을 읽은 적이 있다 — 생성 규칙은 기능 명세만 근거로 적었다.
- Suricata PT·SSRF ANALYTIC sid는 요청 버퍼(http.uri·http.uri.raw)만 본다. 응답 쪽 버퍼 0.
- Wazuh 요청 신호 룰 100220(download)·100240(preview)은 http_request.url.path·args만 본다. 응답 코드·본문 조건 없음.
- 응답에 의존하는 룰은 레거시 attack-logger 그룹(application.log — 100020~100022 level 0, 100071, 100051)뿐이고,
  이 알림에는 data.rid가 없어 R18 c로 연결되지 않는다(미연결 기록만). nginx 그룹 룰은 현재 스택에 nginx 로그 원천이 없다.
- 결론: 업로드 폴더가 비어 다운로드가 404인 것과 preview 외부 연결 결과는 연결 가능한 룰(APP_RULE rid 연결·NIDS)의 발화 조건을 바꾸지 않는다.

## 집합 약어
S_ALL = SUCCEEDED_MISSED + SUCCEEDED_DETECTED + SUCCEEDED_BLOCKED
F_ALL = FAILED_DETECTED + FAILED_UNSEEN
CONCL = 전체 − UNCERTAIN

## 지표 카드
| ID | 지표 | 분자 / 분모 | 분할 | 목표·용도 |
|---|---|---|---|---|
| M01 | Attack Success Rate | S_ALL / CONCL | 전체·시나리오·기법 | 기술 |
| M02 | Detection Rate | (SUCCEEDED_DETECTED + SUCCEEDED_BLOCKED) / S_ALL | 〃 | 주지표 |
| M03 | Miss Rate | SUCCEEDED_MISSED / S_ALL | 〃 | H1: 분자 ≥ 1 / H3: R9 |
| M04 | MTTD | SUCCEEDED_DETECTED ∧ late=false 의 mttd_ms p50·p95 + n | 〃 | late 건 제외(M10) |
| M05 | Correlation Success | 링크 ≥1 시도(UNCERTAIN 포함)의 best source 분포 RID/HEADER/UA_FALLBACK/NONE | 전체(판정)·시나리오(보고) | H2 판정은 전체만: (RID+HEADER) Wilson 하한 ≥ 90% AND NONE Wilson 상한 ≤ 5%. n < 73이면 INCONCLUSIVE(해석: 0건일 때 상한 ≤5%가 되는 최소 n) |
| M06a | Analytic Coverage(존재) | SUCCEEDED_DETECTED ≥1 인 단위 수 / 범위 단위 수 | 기법(T1190·T1110)·시나리오(4종) | MITRE Analytic Coverage 대응 |
| M06b | Analytic Coverage(일관) | 해당 단위 S_ALL ≥ 1 AND SUCCEEDED_MISSED = 0 인 단위 수 / 범위 단위 수 (D2) | 〃 | (해석) 반복 측정 고유 기준 |
| M07a | 텔레메트리 가시성 | 센서 s 원시 이벤트 ≥1 관측 시도 / 전체 시도 | 센서(앱로그·Suricata eve) | MITRE Telemetry·DeTT&CT 대응 (S4-4) |
| M07b | 시도 미탐률 | FAILED_UNSEEN / F_ALL | 시나리오 | 계획서 Visibility Gap 정정 명칭, 상태명 유지 |
| M08 | UNCERTAIN 비율 | UNCERTAIN / 전체 | 전체·시나리오·기법(D5) | 가드레일(R9) |
| M09 | 공격자 판정 정확도 | 일치율·과대평가 수·conclusive n·게이트 상태 | 시나리오 | 결정3 그대로(≥95%, 과대평가 0, n ≥ 20). 게이트 판정 변경은 재측정 run으로만(과거 run 재분류 금지). S3 SSRF FAIL 원인 = ability 단위 fact가 대조군 요청에 귀속된 측정 단위 오류, 재측정 대상. 뷰 값(criteria_met)은 측정값이지 전환 판정 기록이 아니다(D3). |
| M10 | LATE Detection | late=true / (SUCCEEDED_DETECTED + FAILED_DETECTED) | 전체·시나리오 | 기준시각 = alert 생성(timestamp) |
| M11a | Ingestion Lag | alert 생성 → searchable, p50·p95·p99 + n | 소스별 | 하네스 읽기 대기 = 관찰 30s + 소스별 p99 최댓값 (S4-7) |
| M11b | Alert 생성지연 | alertTime − 공격시각, p50·p95·p99 + n | 소스별 | 늦은 alert 링크 상한 = 소스별 p99 최댓값, 배수 없음 (S4-7) |
| M12 | Block Rate | N/A | — | R8 |
| M13 | 통제별 탐지율 | 통제 c가 conf ≥ 0.7 링크를 기여한 S_ALL / c 적용 대상의 S_ALL | 통제 × 시나리오 | APP_RULE=SQLi·PT·SSRF, BACKEND_CORR=BF, NIDS=4종 중 룰 존재분. 룰 없음은 "룰 없음"(0% 아님) |
| M14a | FPR | FP / (FP + TN), 단위 = 정상 요청 1건 | 통제별 | BENIGN run, S4 baseline(목표 없음), 가드레일(R9) |
| M14b | FDR | FP 알림 / (FP 알림 + TP 알림) | 통제별 | 같은 rules_digest의 ATTACK + BENIGN run 묶음 |

## 정합성 불변식(테스트로 고정)
- I1 M02 + M03 = 1 (S_ALL > 0)
- I2 통제 중 하나라도 기여 ⇔ 해당 시도 DETECTED (M13 합집합 = M02 분자)
- I3 UNCERTAIN은 R2 예외 지표 외 어떤 분모에도 없음
- I4 Wilson 구간은 항상 [0, 1] 안, 점추정 포함
- I5 M06b ≤ M06a (D2)
- I6 Σ 시나리오 n(UNKNOWN 포함) = ALL n, Σ 기법 n(UNKNOWN 포함) = ALL n (D1, 검증 기준 M08 — D5)

## 정상 코퍼스(M14) 규칙
- 엔드포인트 기능 명세(정상 사용 패턴)에서 생성. 룰 정규식 참조 금지(순환 검증 방지).
- 정상/공격 라벨은 코퍼스 manifest(정답지 쪽)에만(B안).
- 기존 대조 샘플(laptop--pro, report.pdf 등)은 회귀 세트로 분리, FPR 분모 미포함.
- run당 정상 요청 n ≥ 300(FP 0건일 때 95% 상한 약 1%).

## 결과(Consequences)
- S4-1 measurement_run + run_id 백필(R10 분류),
  S4-2 = 지표 뷰 M01~M06·M07b·M08~M10·M12(N/A), Wilson 함수, R10 상태 뷰, metric_scope 시드, run_id NOT NULL.
  M07a·M13은 S4-4, M14는 S4-5, M11은 S4-7에서 입력이 생길 때 신설. Newcombe(R9)는 S5.
  S4-3 불변 metric_snapshot, S4-4 Suricata 상관 입력 + M07a·M13, S4-5 정상 코퍼스 + M14,
  S4-6 validation-api(독립 빌드, 읽기전용 role), S4-7 M11a·M11b + 링크 상한 확정
- S3-2의 "링크 상한 = Ingestion Lag p99 × 안전계수"는 M11a·M11b 분리로 대체
- 스키마 변경은 push 전 오정현 리뷰(DACI C)
