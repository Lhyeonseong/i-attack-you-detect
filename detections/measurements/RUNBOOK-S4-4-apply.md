# RUNBOOK S4-4 — V6 적용 + 스모크 S4-4-SMOKE (n=1) (초안, 실행: 이현성)

- 목적: ADR-S4-01 v1.7 R14~R16 — NIDS(Suricata 86601) 상관 입력, 텔레메트리 기록(M07a), 통제별 탐지율(M13)을 운영 validation DB 에 적용하고 스모크 1회로 확인
- 성격: **운영 validation DB 쓰기** — (1) V6 마이그레이션, (4) 스모크(실제 공격 1회 + 새 run 1개). 스냅샷(take_metric_snapshot)은 이 RUNBOOK 에서 찍지 않는다
- 위치: 저장소 루트(`docker/.env` 가 있는 develop-v2 체크아웃, S4-4 커밋 이후)
- 계정: `validation_rw`(validation 스키마 소유자, superuser 아님). 비밀값은 `$(grep … docker/.env)` 로만 넘기고 출력하지 않는다
  - `INDEXER_PASSWORD` 는 `.env` 에서 큰따옴표로 감싸져 있어 바깥 따옴표를 벗긴다(`sed`)
- 증거: 모든 명령 출력을 `| tee -a "$LOG"` 로 남긴다 — 먼저 `LOG=detections/measurements/evidence/$(date +%F)_s4-4-apply.log`
- 주의: CampaignRunnerIT(스모크)도 시작할 때 `ValidationSchemaMigrator.migrate` 를 부른다(ValidationPersistenceConfig.java:39).
  (1) 전에 스모크를 돌리면 V6 가 스모크 시작 때 적용된다 — (0)~(2) 를 먼저 끝낸다
- V6 이후 지표 뷰 definition_version 은 `ADR-S4-01 v1.7` 이다(R14 e). 기존 스냅샷(v1.4, 89행 × 2 run)은 그대로 남는다
- 어느 단계든 "멈출 것"이 나오면 다음 단계로 가지 말고 출력 그대로 공유

---

## (0) 사전 점검 (읽기 전용) + 백업

```bash
LOG=detections/measurements/evidence/$(date +%F)_s4-4-apply.log
{ echo "## (0) $(date -u +%FT%TZ)"; git log --oneline -1; git status --porcelain | wc -l; } | tee -a "$LOG"
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
SELECT installed_rank, version, checksum, success FROM validation.flyway_schema_history ORDER BY installed_rank;
SELECT to_regclass('validation.nids_sid_class') AS v6_table;
SELECT count(*) AS detection_links FROM validation.detection_link;
SELECT run_label, definition_version, count(*) FROM validation.metric_snapshot GROUP BY 1, 2 ORDER BY 1;
SELECT count(*) AS smoke_runs FROM validation.measurement_run WHERE label = 'S4-4-SMOKE';
ROLLBACK;
SQL
B=~/capstone-backups/$(date +%F)_validation_pre-v6.sql
test -e "$B" && echo "EXISTS — 덮어쓰지 않음" | tee -a "$LOG" \
  || docker exec postgres sh -c 'pg_dump -U validation_rw -d "$POSTGRES_DB" -n validation --no-owner' > "$B"
ls -l "$B" | tee -a "$LOG"; sha256sum "$B" | tee -a "$LOG"
```

정상 출력 예시:
```
<HEAD 해시> …                      ← S4-4 커밋 이후
0
 1 | 1 | -302875525 | t … 5 | 5 | -644879458 | t     ← V1~V5 만
 v6_table = (빈칸)                                  ← V6 미적용
 detection_links = <N0>                             ← (2) 에서 같은 수여야 함
 S3-GATE-dc66322     | ADR-S4-01 v1.4 | 89
 S4-STACK-6-BASELINE | ADR-S4-01 v1.4 | 89
 smoke_runs = 0
-rw-… <크기> …_validation_pre-v6.sql
```

멈출 것: `flyway_schema_history` 에 6 이 이미 있음(경위 확인), v6_table 이 비어 있지 않음, smoke_runs ≠ 0, 백업 크기 0.

## (1) V6 적용 — migrate 전용 진입점 (측정·Caldera 호출 없음)

```bash
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD' | tee -a "$LOG"
```

정상 출력 예시:
```
    MIGRATE>> before=[1, 2, 3, 4, 5] after=[1, 2, 3, 4, 5, 6]
    MIGRATE>>   rank=6 v=6 nids telemetry by=validation_rw on=<지금> success=true
BUILD SUCCESSFUL in ...
```

멈출 것: `migrate() SKIPPED`(env 미주입), `FAILED`, `Validate failed`·`checksum mismatch`, `after` 에 `6` 없음.

## (2) 사후 확인 (읽기 전용)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
-- (a) control 분포 — 기존 링크 전부 APP_RULE, 수는 (0) 과 같음
SELECT control, count(*) FROM validation.detection_link GROUP BY 1 ORDER BY 1;
-- (b) sid 분류표 시드
SELECT class, count(*) FROM validation.nids_sid_class GROUP BY 1 ORDER BY 1;
SELECT count(*) AS sid_rows FROM validation.nids_sid_class;
-- (c) 통제 목록
SELECT kind, count(*) FROM validation.metric_scope GROUP BY 1 ORDER BY 1;
-- (d) 기존 스냅샷 불변
SELECT run_label, definition_version, count(*) FROM validation.metric_snapshot GROUP BY 1, 2 ORDER BY 1;
-- (e) 라이브 뷰 definition_version, baseline run 의 새 뷰 행 (R14 이전 run → NIDS·M07a 는 NOT_COLLECTED)
SELECT DISTINCT definition_version FROM validation.v_metric_rates;
SELECT metric_id, split_unit, x, n, status FROM validation.v_metric_m13
 WHERE run_id = 'b1c26be1-add2-4d45-8207-0998b0f743b1' ORDER BY 1, 2;
SELECT metric_id, status, count(*) FROM validation.v_metric_m07a
 WHERE run_id = 'b1c26be1-add2-4d45-8207-0998b0f743b1' GROUP BY 1, 2 ORDER BY 1;
ROLLBACK;
SQL
```

정상 출력 예시:
```
 APP_RULE | <N0>
 ANALYTIC 33 / MARKER 4 / TELEMETRY 1 / UNDECIDED 2      sid_rows = 40
 CONTROL 3 / SCENARIO 4 / TECHNIQUE 2
 S3-GATE-dc66322 | ADR-S4-01 v1.4 | 89 ;  S4-STACK-6-BASELINE | ADR-S4-01 v1.4 | 89
 ADR-S4-01 v1.7
 M13_APP_RULE BRUTE_FORCE NULL 20 NOT_APPLICABLE / PATH_TRAVERSAL 60 60 OK / SQLI 0 20 OK / SSRF 40 40 OK
 M13_BACKEND_CORR BRUTE_FORCE 20 20 OK / 그 외 3칸 NULL … NO_RULE
 M13_NIDS 4칸 NULL … NOT_COLLECTED
 M07a_APP_LOG NOT_COLLECTED 5 ; M07a_NIDS NOT_COLLECTED 5
```

(e) M13 값은 baseline verdict(SQLi 20 SUCCEEDED_MISSED, PT 60·BF 20·SSRF 40 SUCCEEDED_DETECTED — 2026-10-21 step0 로그 0-8)에서 손으로 센 값이다.

멈출 것: (a) NIDS 행이 있음·APP_RULE 수 ≠ (0) 의 N0, (b) sid_rows ≠ 40·분류별 수 다름, (c) CONTROL ≠ 3,
(d) 스냅샷 행 수 변화·v1.7 행이 있음(스냅샷은 찍지 않았다), (e) definition_version ≠ v1.7, M13 값이 위와 다름.

## (3) 스모크 S4-4-SMOKE 사전 조건 (ADR-S4-03 D9, 읽기 전용)

RUNBOOK-S4-1b-smoke.md 의 같은 절을 그대로 실행하고 출력을 `| tee -a "$LOG"` 로 남긴다.

- (0-b) Caldera operation: `running=`·`paused=` 줄이 없음 (0개)
- (0) agent 조회: `red` 그룹 `trusted=true` 이고 `last_seen` 이 지금으로부터 수십 초 이내인 agent 가 정확히 1개 (없으면 (1) sandcat 기동)
- (0-c) 인터페이스 짝: app0·atk0·imds0·sec0 이 각 서브넷 안, `eth_count=0`, suricata `-i app0 -i atk0 -i imds0`, `NM_OK`
- (0-d) Suricata 출력: `outputs.N stats enabled=no`, `eve-log.types.N stats enabled=no`, alert·http·files·flow 줄 존재
- 추가: label `S4-4-SMOKE` run 0개 ((0) 의 smoke_runs), eve.json 읽기 확인

```bash
docker compose -f docker/docker-compose.yml -p security-lab exec -T suricata sh -c 'wc -c < /var/log/suricata/eve.json' | tee -a "$LOG"
```

멈출 것: 위 조건 중 하나라도 다름, eve.json 읽기 실패·0 bytes.

## (4) 스모크 측정 실행 (n=1, 약 3~4분)

```bash
{ echo "## (4) start=$(date -u +%FT%TZ)"; } | tee -a "$LOG"
RUN_CALDERA_MEASURE=1 MEASURE_N=1 MEASURE_LABEL='S4-4-SMOKE' \
APP_CALDERA_APIKEY="$(grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | cut -d= -f2-)" \
INDEXER_USERNAME="$(grep -m1 '^INDEXER_USERNAME=' docker/.env | cut -d= -f2-)" \
INDEXER_PASSWORD="$(grep -m1 '^INDEXER_PASSWORD=' docker/.env | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/')" \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.measure.CampaignRunnerIT' -i 2>&1 \
  | grep -E 'MEASURE>>|PER-RUN|  \[|NIDS op=|GATE|RUN run_id|op_id 교차검증|Caldera operation 조회 실패|NIDS http|NIDS alert|CampaignRunnerIT|FAILED|BUILD' \
  | tee -a "$LOG"
{ echo "## (4) end=$(date -u +%FT%TZ)"; } | tee -a "$LOG"
```

정상 출력 예시 (값은 실행마다 다를 수 있음 — 행 수·구성이 요점, NIDS 수는 baseline 1 op 평균 참고):
```
    PER-RUN op=<Caldera operation UUID> rows=8
    NIDS op=<같은 UUID> alerts=≈101 orphan=0 analytic=≈8 linked=≈8 telemetry=13 marker=80 undecided=0 unclassified=0 http=≈23 attributed=20
    RUN run_id=<run UUID> R10=Result[status=VALID, reason=ATTACK 7, CONTROL 1 = expected]
BUILD SUCCESSFUL in ...
```
(baseline 20 op 합계: ANALYTIC 1000020 60·1000031 20·1000032 42·1000060 40, MARKER 1000001~4 각 400, TELEMETRY 1000030 260 — step0 로그 0-4. attributed 20 = op 당 요청 20건)

멈출 것: `orphan=` 이 0 이 아님, `NIDS op=` 줄이 없음, `NIDS alert … 검색 상한 초과`, `Caldera operation 조회 실패`(NIDS 연결 없음),
`op_id 교차검증 불일치`, `rows=` ≠ 8, `R10=…INVALID`, `FAILED`, `measure() SKIPPED`.

## (5) 스모크 판정 (읽기 전용)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
-- (a) R10
SELECT label, r10_status, actual_attack, actual_control FROM validation.v_run_integrity WHERE label = 'S4-4-SMOKE';
-- (b) verdict 가 S4-STACK-3-SMOKE 와 같은가 — 차이 행 0 이어야 함
WITH s AS (
    SELECT r.label, v.scenario, v.unit_type, v.attempt_role, v.verdict, count(*) AS n
    FROM validation.measurement_run r JOIN validation.verdict_result v ON v.run_id = r.run_id
    WHERE r.label IN ('S4-4-SMOKE', 'S4-STACK-3-SMOKE') GROUP BY 1, 2, 3, 4, 5)
SELECT coalesce(a.scenario, b.scenario) AS scenario, coalesce(a.unit_type, b.unit_type) AS unit_type,
       coalesce(a.attempt_role, b.attempt_role) AS role, coalesce(a.verdict, b.verdict) AS verdict,
       a.n AS smoke_4_4, b.n AS stack_3
FROM (SELECT * FROM s WHERE label = 'S4-4-SMOKE') a
FULL JOIN (SELECT * FROM s WHERE label = 'S4-STACK-3-SMOKE') b
  USING (scenario, unit_type, attempt_role, verdict)
WHERE a.n IS DISTINCT FROM b.n;
-- (c) NIDS 링크 시나리오별 (PT·BF·SSRF ≥ 1, SQLi 0) / (d) ANALYTIC 아닌 sid 의 NIDS 링크 0
SELECT v.scenario, count(*) AS nids_links,
       count(*) FILTER (WHERE k.class IS DISTINCT FROM 'ANALYTIC') AS non_analytic_links
FROM validation.measurement_run r
JOIN validation.verdict_result v ON v.run_id = r.run_id
JOIN validation.verdict_member m ON m.verdict_id = v.id
JOIN validation.detection_link l ON l.correlation_id = m.correlation_id AND l.control = 'NIDS'
LEFT JOIN validation.nids_sid_class k ON k.sid::text = l.rule_id
WHERE r.label = 'S4-4-SMOKE' GROUP BY 1 ORDER BY 1;
-- (e) BF compromise
SELECT unit_type, verdict, compromise_detected FROM validation.verdict_result v
JOIN validation.measurement_run r ON r.run_id = v.run_id
WHERE r.label = 'S4-4-SMOKE' AND v.scenario = 'BRUTE_FORCE';
-- (f) M13·M07a 행 / (g) orphan
SELECT 'm13' AS v, count(*), count(*) FILTER (WHERE status = 'NOT_COLLECTED') AS not_collected
  FROM validation.v_metric_m13 x JOIN validation.measurement_run r ON r.run_id = x.run_id WHERE r.label = 'S4-4-SMOKE'
UNION ALL
SELECT 'm07a', count(*), count(*) FILTER (WHERE status = 'NOT_COLLECTED')
  FROM validation.v_metric_m07a x JOIN validation.measurement_run r ON r.run_id = x.run_id WHERE r.label = 'S4-4-SMOKE';
SELECT windows, nids_alerts, orphan_alerts, analytic_alerts, analytic_linked, marker_alerts, telemetry_alerts,
       undecided_alerts, unclassified_alerts, http_events, http_attributed
  FROM validation.v_nids_run_stat s JOIN validation.measurement_run r ON r.run_id = s.run_id WHERE r.label = 'S4-4-SMOKE';
-- (h) 기록만 (판정 기준 아님, R14 e): 시나리오별 MTTD 와 첫 탐지 통제 (conf ≥ 0.7 ∧ technique 일치 링크 중 가장 이른 것)
SELECT v.scenario, v.unit_type, v.verdict, v.mttd_ms,
       (SELECT l.control || ':' || l.rule_id FROM validation.verdict_member m
          JOIN validation.detection_link l ON l.correlation_id = m.correlation_id
         WHERE m.verdict_id = v.id AND l.confidence >= 0.7 AND l.technique IS NOT DISTINCT FROM v.technique_id
         ORDER BY l.alert_time, l.control LIMIT 1) AS first_control
FROM validation.verdict_result v JOIN validation.measurement_run r ON r.run_id = v.run_id
WHERE r.label = 'S4-4-SMOKE' ORDER BY v.scenario, v.mttd_ms;
SELECT metric_id, split_unit, x, n, status FROM validation.v_metric_m13 x
  JOIN validation.measurement_run r ON r.run_id = x.run_id WHERE r.label = 'S4-4-SMOKE' ORDER BY 1, 2;
SELECT metric_id, split_kind, split_unit, x, n, status FROM validation.v_metric_m07a x
  JOIN validation.measurement_run r ON r.run_id = x.run_id WHERE r.label = 'S4-4-SMOKE' ORDER BY 1, 2, 3;
ROLLBACK;
SQL
```

판정 기준(전부 만족해야 통과):
- (a) `VALID`, 7 / 1
- (b) 차이 행 0 (verdict 가 S4-STACK-3-SMOKE 와 같다 — SQLi SUCCEEDED_MISSED 1, PT 3·BF 1·SSRF 2 SUCCEEDED_DETECTED, 대조 FAILED_UNSEEN 1)
- (c) NIDS 링크 PATH_TRAVERSAL ≥ 1, BRUTE_FORCE ≥ 1, SSRF ≥ 1, SQLI 행 없음
- (d) non_analytic_links 전부 0 (MARKER 링크 0)
- (e) BF_SEQUENCE 1행, `compromise_detected = t`
- (f) m13 12행·m07a 10행, not_collected 0
- (g) windows 1, orphan_alerts 0
- (h) 기록만 — MTTD 는 비교 기준이 아니다(NIDS 링크가 판정에 들어가 첫 탐지 통제가 바뀔 수 있다, R14 e)

멈출 것: 위 기준 중 하나라도 다름 — 통과로 기록하지 말고 출력 원문을 증거 로그에 남긴 뒤 DRI 판단.

## (6) 마무리

- (4) 의 sandcat 창 종료(`Ctrl-C`)
- 스모크가 만든 `detections/measurements/gate-report-<iso>.md/.json` 은 스모크 증거 — 보관 여부 결정(커밋 시 explicit pathspec)
- 증거 로그를 explicit pathspec 으로 커밋(`git commit -- "$LOG"`)
- S4-4-SMOKE 는 스냅샷 대상이 아니다(새 baseline 20회는 S4-7 이후 — R14 e)
