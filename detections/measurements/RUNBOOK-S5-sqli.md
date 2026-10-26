# RUNBOOK S5 — SQLi 미탐 룰 개선 Before/After (Gap #7, 룰 100211 추가, 실행: 이현성)

- 목적: ADR-S5-01 — 앱 룰 100211(요청 신호 확장) 추가로 SQLi Miss Rate(M03 SQLI)가 유의 감소하는지, 정상 오탐(M14a)이 늘지 않는지 한 변수로 측정.
- 성격: **룰 배포(wazuh.manager 재시작)** + **운영 validation DB 쓰기**(V10, After ATTACK 20 op run, After BENIGN WEB run, 스냅샷 2개).
- Before(비교 대상, 기존 스냅샷): `S4-STACK-6-BASELINE`(ATTACK), `S4-5-BENIGN-WEB-R2`(BENIGN). After: `S5-SQLI-AFTER`(ATTACK), `S5-SQLI-AFTER-BENIGN-WEB`(BENIGN, 같은 WEB 코퍼스 960).
- 변경은 `vuln_rules.xml` 100211 1개(rules_digest 바뀜, A4). 공격·Suricata·엔진·target-web·V1~V9 불변.
- 증거: 모든 출력 `| tee -a "$LOG"` — 먼저 `LOG=detections/measurements/evidence/2026-10-22_s5-sqli-before-after.log`.
- 홀드아웃: 룰은 정상 코퍼스를 보지 않고 작성됨(ADR-S5-01). 측정은 기존 WEB 코퍼스(변경 없음)로 한다.
- 어느 단계든 "멈출 것"이 나오면 다음 단계로 가지 말고 출력 그대로 공유.

---

## (0) 사전 점검 (읽기 전용) + 백업

```bash
LOG=detections/measurements/evidence/2026-10-22_s5-sqli-before-after.log
{ echo "## (0) $(date -u +%FT%TZ)"; git log --oneline -1; git status --porcelain | wc -l; } | tee -a "$LOG"
# Caldera running/paused 0 (S4-5 (0) 와 동일), sandcat 꺼짐
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
SELECT installed_rank, version, success FROM validation.flyway_schema_history ORDER BY installed_rank;  -- V1~V9
SELECT count(*) AS same_label FROM validation.measurement_run WHERE label IN ('S5-SQLI-AFTER', 'S5-SQLI-AFTER-BENIGN-WEB');
SELECT label, run_id FROM validation.measurement_run WHERE label IN ('S4-STACK-6-BASELINE', 'S4-5-BENIGN-WEB-R2');
SELECT count(*) AS snapshot_rows FROM validation.metric_snapshot;
ROLLBACK;
SQL
B=~/capstone-backups/$(date +%F)_validation_pre-v10.sql
test -e "$B" && echo "EXISTS — 덮어쓰지 않음" | tee -a "$LOG" \
  || docker exec postgres sh -c 'pg_dump -U validation_rw -d "$POSTGRES_DB" -n validation --no-owner' > "$B"
ls -l "$B" | tee -a "$LOG"; sha256sum "$B" | tee -a "$LOG"
```
이어서 RUNBOOK-S4-1b-smoke.md (0-b)(0-c)(0-d)(스택·인터페이스·Suricata) 그대로 실행하고 `| tee -a "$LOG"`.
멈출 것: running/paused op 있음, sandcat 있음, flyway 에 10 이 이미 있음, same_label ≠ 0, before run 2개가 안 보임, 백업 크기 0.

## (1) V10 적용 — 비교 함수 (migrate 전용 진입점) **[STOP: 실행 전 승인]**

```bash
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD' | tee -a "$LOG"
```
정상: `before=[1, …, 9] after=[1, …, 10]`, rank 10 `snapshot compare`. 지표 뷰·기존 스냅샷·R10 불변 읽기 확인.
멈출 것: after 에 10 없음, 기존 스냅샷·R10 변화.

## (2) 룰 배포 — wazuh.manager 재시작 **[STOP: 룰 배포(재시작) 전 승인]**

- bind-mount 는 단일 파일이라 호스트 수정이 컨테이너에 바로 안 보인다(inode) → 서비스 재생성/재시작 필요(known-gaps Wazuh single-file bind-mount).
- 배포 전 B3(임시 manager logtest, `/tmp/s5-sqli-logtest.sh`)로 100211 양성·음성이 통과했는지 먼저 확인(운영 manager 안 건드림).

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2/docker
docker compose restart wazuh.manager 2>&1 | tee -a "$LOG"
# agent Active + 룰 로드 오류 0 + 100211 로드 확인
docker exec security-lab-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>&1 | tee -a "$LOG"
docker exec security-lab-wazuh.manager-1 sh -c '/var/ossec/bin/wazuh-logtest -v 2>&1 | head -1' | tee -a "$LOG"
docker exec security-lab-wazuh.manager-1 grep -c "rule_id.*100211\|Rule '\''100211'\''" /var/ossec/logs/ossec.log | tee -a "$LOG" || true
```
멈출 것: agent 가 Active 아님, ossec.log 에 룰 로드 오류(`Error`·`Invalid`)·100211 로드 실패.

## (3) 배포 스모크 1회 **[STOP: 측정 시작 전 승인]**

정상 스택에 SQLi `'` 1건 + 정상 검색 1건을 보내(스크립트 `/tmp/s5-sqli-smoke.sh`), 인덱서에서 100211 발동/미발동 확인.
멈출 것: `'` 요청이 100211 로 안 잡힘, 정상 검색이 100211 로 잡힘(설계상 따옴표 없는 정상어).

## (4) After ATTACK 20회 **[STOP: 측정 시작 전 승인]**

```bash
RUN_CALDERA_MEASURE=1 MEASURE_N=20 MEASURE_LABEL='S5-SQLI-AFTER' \
POSTGRES_DB=... VALIDATION_DB_PASSWORD=... (S4-1b-smoke (3) 과 같은 env) \
./gradlew cleanTest test --tests 'com.capstone.vuln.measure.CampaignRunnerIT' -i 2>&1 | tee -a "$LOG"
```
정상: run CLOSED, R10 VALID, rules_digest 가 Before 와 다름(100211 추가분). 멈출 것: R10 ≠ VALID, 게이트 PT·BF·SSRF 분포가 Before 와 다름(가드레일2).

## (5) After BENIGN WEB **[STOP: 측정 시작 전 승인]**

RUNBOOK-S4-5-benign.md (3) 과 같은 절차·가드(CA·git clean·사전시험), `BENIGN_LABEL='S5-SQLI-AFTER-BENIGN-WEB'`.
정상: `matched=960/960`, R10 VALID, rules_digest 가 After ATTACK 과 같음(M14b 짝 성립). 멈출 것: matched ≠ 960, R10 ≠ VALID.

## (6) 스냅샷 2개 **[STOP: (4)(5) 재확인 후 실행 전 승인]**

각 After run 을 `take_metric_snapshot(:'run')`(RUNBOOK-S4-5 (4-S) 두 겹 방어 방식). ATTACK 스냅샷 definition_version = Before ATTACK 과 같아야 compare 성립. BENIGN = M14 v2.0.
멈출 것: definition_version 이 Before 와 다름, 스냅샷 거부.

## (7) 비교·판정표

### (7-R7) 선행 — Before 를 현재 definition_version 으로 재스냅샷 (운영 DB 쓰기 **[STOP]**)

Before 스냅샷은 과거 정의로 찍혀 있다(ATTACK v1.4·BENIGN v1.9). After 는 현재 정의(ATTACK v1.7·BENIGN v2.0).
같은 definition_version 행끼리만 비교할 수 있으므로, ADR R7 대로 Before 2개를 **현재 정의로 추가 스냅샷**한다(기존 과거-정의 행은 불변, 새 정의 행만 추가, 같은 run+정의 중복이면 함수가 거부).

```bash
# 각 run 전후 총행·지문 불변 확인하며 2회만. (실제 절차는 /tmp/s5-7b-compare.sh 참조)
SELECT validation.take_metric_snapshot((SELECT run_id FROM validation.measurement_run WHERE label='S4-STACK-6-BASELINE'));
SELECT validation.take_metric_snapshot((SELECT run_id FROM validation.measurement_run WHERE label='S4-5-BENIGN-WEB-R2'));
```

### (7) 비교 (읽기 전용) — compare_snapshots 함수 대신 "같은 def 행끼리" 직접 join

`compare_snapshots()` 는 before/after 의 definition_version 이 다르면 RAISE 하는 가드가 있어, R7 로 Before 에 과거+현재 두 정의가 공존하면
join 이 과거-정의 행까지 섞여 RAISE 한다. 따라서 비교는 **같은 definition_version 행끼리 직접 join + newcombe_diff_ci** 로 한다
(차기 V11 에서 compare_snapshots 를 definition_version 까지 join 하도록 개정 — Gap #14 와 함께).

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
-- 주지표 M03 SQLI (ATTACK) / 가드레일1 M14a_APP_RULE (BENIGN) — (x1,n1)=After, (x2,n2)=Before
SELECT a.metric_id, a.scope_key, a.numerator x1, a.denominator n1, b.numerator x2, b.denominator n2,
       round(d.diff::numeric,6) diff, round(d.lo::numeric,6) lo, round(d.hi::numeric,6) hi
FROM validation.metric_snapshot a
JOIN validation.metric_snapshot b
  ON a.metric_id=b.metric_id AND a.scope_kind=b.scope_kind AND a.scope_key=b.scope_key
  AND a.definition_version=b.definition_version            -- 같은 def 행끼리만
LEFT JOIN LATERAL validation.newcombe_diff_ci(a.numerator,a.denominator,b.numerator,b.denominator) d ON true
WHERE (a.run_id=(SELECT run_id FROM validation.measurement_run WHERE label='S5-SQLI-AFTER')
       AND b.run_id=(SELECT run_id FROM validation.measurement_run WHERE label='S4-STACK-6-BASELINE')
       AND a.metric_id='M03' AND a.scope_key='SQLI')
   OR (a.run_id=(SELECT run_id FROM validation.measurement_run WHERE label='S5-SQLI-AFTER-BENIGN-WEB')
       AND b.run_id=(SELECT run_id FROM validation.measurement_run WHERE label='S4-5-BENIGN-WEB-R2')
       AND a.metric_id='M14a_APP_RULE')
ORDER BY a.metric_id, a.scope_key;
ROLLBACK;
SQL
```
판정(ADR-S5-01):
- PASS: M03 SQLI Newcombe 상한(hi) < 0.
- 가드레일1 FAIL: M14a_APP_RULE 어느 엔드포인트든 Newcombe 하한(lo) > 0.
- 가드레일2: After ATTACK 게이트 분포·M09 일치율 = Before. 가드레일3: 두 run R10 VALID, rules_digest 변경, 그 외 스택 digest 동일 — **engine_version 동일성도 확인(Gap #14, 측정 후 발견)**.

## (8) 마무리

- known-gaps Gap #7 상태 갱신(100211 추가·측정 결과·판정), /tmp 로그를 증거 로그에 이어 붙여 explicit pathspec 커밋.
- 다음 후보(ADR-S5-01 "하지 않는 것"): Suricata 1000013, 페이로드 추가, login NIDS, target-web 5xx 반환화.
