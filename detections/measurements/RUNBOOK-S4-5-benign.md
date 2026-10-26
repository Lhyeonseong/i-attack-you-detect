# RUNBOOK S4-5 — V7 적용 + BENIGN run S4-5-BENIGN-WEB(-R2) (정상 코퍼스, 실행: 이현성)

- 목적: ADR-S4-01 v1.8 R17·R18 — 정상 코퍼스(search·download·preview 각 320건)를 Caldera 없이 보내 M14a(FPR)·M14b(FDR)를 산출
- 범위: 웹 run 만. login run 은 S4-5 범위 안 별도 작업(R17 e) — S4-5 완료 = 두 run 모두 R10 VALID + 스냅샷
- 성격: **운영 validation DB 쓰기** — (1) V7, (3) 새 BENIGN run 1개(요청 960행·판정 1920행), (4) 스냅샷. target-web 에 정상 요청 960건
- **외부 연결**: preview 320건은 target-web 이 코퍼스의 공개 URL(40개 사이트, 사이트당 최대 12건)을 직접 가져온다(연결·응답 각 3 s 타임아웃)
- 위치: 저장소 루트(`docker/.env` 가 있는 develop-v2 체크아웃, S4-5 커밋 이후)
- 계정: `validation_rw`. 비밀값은 `$(grep … docker/.env)` 로만 넘기고 출력하지 않는다(`INDEXER_PASSWORD` 는 바깥 큰따옴표를 `sed` 로 벗긴다)
- 증거: 모든 명령 출력을 `| tee -a "$LOG"` — 먼저 `LOG=detections/measurements/evidence/2026-10-22_s4-5-benign.log`
- 주의: CampaignRunnerIT 는 시작할 때 migrate 한다 — 이 RUNBOOK 이 끝날 때까지 공격 측정을 돌리지 않는다. BenignRunIT 는 migrate 하지 않고 V7 이 아니면 실패한다
- 어느 단계든 "멈출 것"이 나오면 다음 단계로 가지 말고 출력 그대로 공유

---

## (0) 사전 조건 (읽기 전용) + 백업

```bash
LOG=detections/measurements/evidence/2026-10-22_s4-5-benign.log
{ echo "## (0) $(date -u +%FT%TZ)"; git log --oneline -1; git status --porcelain | wc -l; } | tee -a "$LOG"
# Caldera: running/paused operation 0, agent 비콘 없음(sandcat 꺼짐)
grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 10 -H @- http://127.0.0.1:8888/api/v2/operations \
  | jq -r '"total=\(length)", (group_by(.state)[] | "\(.[0].state)=\(length)")' | tee -a "$LOG"
grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 5 -H @- http://127.0.0.1:8888/api/v2/agents \
  | jq -r '.[] | [.paw, .group, (.trusted|tostring), .last_seen] | @tsv' | tee -a "$LOG"; date -u +%FT%TZ | tee -a "$LOG"
pgrep -af sandcat | tee -a "$LOG" || echo "sandcat process: none" | tee -a "$LOG"
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
SELECT installed_rank, version, success FROM validation.flyway_schema_history ORDER BY installed_rank;
SELECT count(*) AS same_label FROM validation.measurement_run WHERE label = 'S4-5-BENIGN-WEB';
SELECT md5(string_agg(run_id || '|' || r10_status || '|' || coalesce(r10_reason, '-'), ',' ORDER BY run_id)) AS r10_md5,
       count(*) AS runs FROM validation.v_run_integrity;
SELECT count(*) AS snapshot_rows FROM validation.metric_snapshot;
ROLLBACK;
SQL
B=~/capstone-backups/$(date +%F)_validation_pre-v7.sql
test -e "$B" && echo "EXISTS — 덮어쓰지 않음" | tee -a "$LOG" \
  || docker exec postgres sh -c 'pg_dump -U validation_rw -d "$POSTGRES_DB" -n validation --no-owner' > "$B"
ls -l "$B" | tee -a "$LOG"; sha256sum "$B" | tee -a "$LOG"
```

이어서 RUNBOOK-S4-1b-smoke.md 의 (0-c) 인터페이스 짝·(0-d) Suricata 출력 확인을 그대로 실행하고 `| tee -a "$LOG"`.

정상 출력 예시:
```
total=<N> / finished=<N>                  ← running= / paused= 줄 없음
<paw> red false <수 시간 이상 전>          ← trusted=true 이고 last_seen 이 최근인 agent 없음
sandcat process: none
 … 6 | 6 | t                              ← V1~V6 만
 same_label = 0
 r10_md5 = <값 A>  runs = <N>              ← (2) 에서 같아야 함
 snapshot_rows = <N1>
-rw-… <크기> …_validation_pre-v7.sql
```

멈출 것: running·paused operation 있음, 살아 있는 agent 또는 sandcat 프로세스 있음, flyway 에 7 이 이미 있음, same_label ≠ 0,
(0-c)·(0-d) 기준 불일치, 백업 크기 0.

## (1) V7 적용 — migrate 전용 진입점 **[STOP 2: 실행 전 승인]**

```bash
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD' | tee -a "$LOG"
```

정상 출력 예시:
```
    MIGRATE>> before=[1, 2, 3, 4, 5, 6] after=[1, 2, 3, 4, 5, 6, 7]
    MIGRATE>>   rank=7 v=7 benign m14 by=validation_rw on=<지금> success=true
BUILD SUCCESSFUL in ...
```

멈출 것: `migrate() SKIPPED`, `FAILED`, `Validate failed`·`checksum mismatch`, `after` 에 `7` 없음.

## (2) 사후 확인 (읽기 전용)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$LOG"
BEGIN READ ONLY;
SELECT endpoint, scenario, param FROM validation.benign_endpoint ORDER BY endpoint;
-- 기존 run 의 R10 판정 불변 ((0) 의 값 A 와 같아야 함)
SELECT md5(string_agg(run_id || '|' || r10_status || '|' || coalesce(r10_reason, '-'), ',' ORDER BY run_id)) AS r10_md5,
       count(*) AS runs FROM validation.v_run_integrity;
SELECT count(*) AS snapshot_rows, count(paired_run_id) AS paired FROM validation.metric_snapshot;
SELECT count(*) AS benign_rows FROM validation.benign_request;
ROLLBACK;
SQL
```

정상 출력 예시:
```
 /api/files/download | PATH_TRAVERSAL | filename
 /api/preview        | SSRF           | url
 /api/products/search| SQLI           | keyword
 r10_md5 = <값 A>  runs = <N>
 snapshot_rows = <N1> | paired = 0
 benign_rows = 0
```

멈출 것: benign_endpoint 가 3행이 아님, r10_md5·runs 가 (0) 과 다름, snapshot_rows 변화·paired ≠ 0, benign_rows ≠ 0.

## (3-F) 1차 run 실패 처리 (2026-10-22, run dffb77a7 — 인덱서 TLS 호스트명 검증, 알림 읽기 전 중단) — 실행 완료

원인·조치: 증거 로그 (3-F), known-gaps Gap #12. 1차 run 은 지우지 않고 INVALID 로 닫는다(ADR-S4-03 D5, 재측정은 -R2).
**운영 DB 쓰기 — 현성 실행.** 대상이 OPEN 1행일 때만 바뀐다. 출력은 저장소 밖 `/tmp/s4-5-close.log`(작업 트리를 깨끗이 — (3) 가드),
(3) 이 끝날 때 증거 로그에 이어 붙인다. (2026-10-22 실행: 1차는 아래 SELECT 의 `label` 모호 오류로 COMMIT 전 중단·롤백, 열 접두를 붙인 2차에서 UPDATE 1)

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee /tmp/s4-5-close.log
BEGIN;
UPDATE validation.measurement_run
   SET status = 'CLOSED', ended_at = now(), notes = 'aborted: indexer TLS hostname verification, alerts not read'
 WHERE run_id = 'dffb77a7-0b43-4322-acd7-d943240b11b5' AND label = 'S4-5-BENIGN-WEB' AND kind = 'BENIGN' AND status = 'OPEN';
SELECT r.label, r.status, r.ended_at IS NOT NULL AS ended, r.notes, i.r10_status, i.r10_reason, i.benign_loaded
  FROM validation.measurement_run r JOIN validation.v_run_integrity i ON i.run_id = r.run_id
 WHERE r.run_id = 'dffb77a7-0b43-4322-acd7-d943240b11b5';
COMMIT;
SQL
```

정상: `UPDATE 1`, `CLOSED | t | aborted: … | INVALID | BENIGN_LOAD_MISMATCH | 0`. 멈출 것: `UPDATE 0`(이미 닫혔거나 대상 다름).

## (3) BENIGN run 측정 S4-5-BENIGN-WEB-R2 **[STOP 3: 실행 전 승인]** — 실행 완료(run 3818e21a, R10 VALID 960/960/960)

- git_dirty = f 로 측정한다: 그 전 증거 로그를 먼저 커밋해 작업 트리를 깨끗이 하고, 측정 중 출력은 저장소 밖 `/tmp/s4-5-r2.log` 에 쓴다.
  끝난 뒤 증거 로그에 이어 붙인다(BenignRunIT 도 작업 트리가 깨끗하지 않으면 run 을 열지 않는다).
- 인덱서 루트 CA: 호스트 원본(docker/config/wazuh_indexer_ssl_certs/root-ca.pem)은 root 0500 이라 측정 사용자가 못 읽는다 →
  인덱서 컨테이너가 마운트해 쓰는 같은 파일 **root-ca.pem 한 파일만** 저장소 밖에 복사한다. 같은 디렉터리의 root-ca.key(CA 개인키)와
  다른 *.key·*-key.pem 은 복사하지 않는다. 사본은 인증서 1개·개인키 블록 0개·지문(known-gaps Gap #12) 일치를 확인한다.

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2
LOG=detections/measurements/evidence/2026-10-22_s4-5-benign.log
RLOG=/tmp/s4-5-r2.log
: > "$RLOG"
mkdir -p ~/capstone-certs
docker exec security-lab-wazuh.indexer-1 sh -c 'cat /usr/share/wazuh-indexer/config/certs/root-ca.pem' \
  > ~/capstone-certs/wazuh-indexer-root-ca.pem
chmod 0644 ~/capstone-certs/wazuh-indexer-root-ca.pem
CA_FP=$(openssl x509 -in ~/capstone-certs/wazuh-indexer-root-ca.pem -noout -fingerprint -sha256 | cut -d= -f2)
CA_CERTS=$(grep -c 'BEGIN CERTIFICATE' ~/capstone-certs/wazuh-indexer-root-ca.pem)
CA_KEYS=$(grep -c 'PRIVATE KEY' ~/capstone-certs/wazuh-indexer-root-ca.pem || true)
{ echo "## (3-CA) $(date -u +%FT%TZ)"; ls -l ~/capstone-certs; \
  echo "ca_fingerprint=$CA_FP ca_certificates=$CA_CERTS private_key_blocks=$CA_KEYS"; } | tee -a "$RLOG"

{ echo "## (3-0) pre-check $(date -u +%FT%TZ)"; git log --oneline -1; } | tee -a "$RLOG"
DIRTY=$(git status --porcelain | wc -l)
RP=$(grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 10 -H @- http://127.0.0.1:8888/api/v2/operations \
  | jq '[.[] | select(.state == "running" or .state == "paused")] | length')
ALIVE=$(grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 5 -H @- http://127.0.0.1:8888/api/v2/agents \
  | jq '[.[] | select(.trusted == true)] | length')
SANDCAT=$(pgrep -fc sandcat || true)
echo "dirty_files=$DIRTY running_or_paused_ops=$RP trusted_agents=$ALIVE sandcat_procs=$SANDCAT" | tee -a "$RLOG"

if [ "$DIRTY" = "0" ] && [ "$RP" = "0" ] && [ "$ALIVE" = "0" ] && [ "$SANDCAT" = "0" ] \
   && [ "$CA_CERTS" = "1" ] && [ "$CA_KEYS" = "0" ] \
   && [ "$CA_FP" = "D4:6F:19:39:CF:B1:CA:F7:F4:04:7D:7F:5F:38:59:D1:18:13:6C:33:AC:E8:F0:52:67:D0:D6:C9:6F:B5:FD:F6" ]; then
  { echo "## (3) start=$(date -u +%FT%TZ)"; } | tee -a "$RLOG"
  RUN_BENIGN_MEASURE=1 BENIGN_LABEL='S4-5-BENIGN-WEB-R2' \
  INDEXER_CA_FILE="$HOME/capstone-certs/wazuh-indexer-root-ca.pem" \
  POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
  VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
  INDEXER_USERNAME="$(grep -m1 '^INDEXER_USERNAME=' docker/.env | cut -d= -f2-)" \
  INDEXER_PASSWORD="$(grep -m1 '^INDEXER_PASSWORD=' docker/.env | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/')" \
  ./gradlew cleanTest test --tests 'com.capstone.vuln.measure.BenignRunIT' -i 2>&1 \
    | grep -E 'BENIGN>>|BenignRunIT|FAILED|BUILD|검색 상한|필요 \(기본값 없음\)|깨끗하지|INDEXER_CA_FILE' | tee -a "$RLOG"
  { echo "## (3) end=$(date -u +%FT%TZ)"; } | tee -a "$RLOG"
else
  echo "STOP: 사전 조건 불일치 — 측정하지 않음 (dirty_files=$DIRTY running_or_paused_ops=$RP trusted_agents=$ALIVE sandcat_procs=$SANDCAT ca_certificates=$CA_CERTS private_key_blocks=$CA_KEYS ca_fingerprint=$CA_FP)" | tee -a "$RLOG"
fi

{ echo; echo "## (3-F) run dffb77a7 close (from /tmp/s4-5-close.log)"; cat /tmp/s4-5-close.log; \
  echo; echo "## (3) R2 run log (from $RLOG)"; cat "$RLOG"; } >> "$LOG"
```

정상: `ca_certificates=1 private_key_blocks=0`, `dirty_files=0 … sandcat_procs=0`, `preflight indexer OK`, `matched=960/960 unmatched_untagged_lines=0`,
`R10={r10_status=VALID, … benign_loaded=960, benign_matched=960}`. 멈출 것: `STOP: 사전 조건 불일치`, preflight 실패, matched ≠ 960,
unmatched > 0, R10 ≠ VALID, `검색 상한`, `FAILED`, `measure() SKIPPED`. 실패해 run 이 OPEN 으로 남아도 benign_request(전송 기록)는 보존된다.

## (4) R10·M14 확인 (읽기 전용, 출력은 /tmp/s4-5-4.log → 나중에 증거 로그에 이어 붙임)

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2
OUT=/tmp/s4-5-4.log
: > "$OUT"
RUN=$(docker exec postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -c "SELECT run_id FROM validation.measurement_run WHERE label = '"'"'S4-5-BENIGN-WEB-R2'"'"'"')
CA=~/capstone-certs/wazuh-indexer-root-ca.pem
echo "run=$RUN" | tee -a "$OUT"

# (4-a) R10 + 측정 창(첫 전송 − 1s ~ 마지막 응답 + 관찰 30s)
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL' | tee -a "$OUT"
BEGIN READ ONLY;
SELECT i.label, i.status, i.r10_status, i.r10_reason, i.expected_attempts, i.benign_loaded, i.benign_matched
  FROM validation.v_run_integrity i WHERE i.run_id = :'run';
SELECT q.endpoint, q.status, count(*) FROM validation.benign_request q WHERE q.run_id = :'run' GROUP BY 1, 2 ORDER BY 1, 2;
ROLLBACK;
SQL
WIN_FROM=$(docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -v run='"$RUN" <<'SQL'
SELECT to_char((min(q.sent_at) - interval '1 second') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM validation.benign_request q WHERE q.run_id = :'run';
SQL
)
WIN_TO=$(docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -v run='"$RUN" <<'SQL'
SELECT to_char((max(q.responded_at) + interval '30 seconds') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM validation.benign_request q WHERE q.run_id = :'run';
SQL
)
echo "window from=$WIN_FROM to=$WIN_TO" | tee -a "$OUT"

# (4-b) 미연결 앱 알림 — DB(rule_id 별) + 인덱서(rule.id × location, data.rid 유무). CA 체인 + 호스트명 검증, 인증 헤더는 stdin
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL' | tee -a "$OUT"
BEGIN READ ONLY;
SELECT u.sensor, u.rule_id, u.reason, count(*) FROM validation.benign_unlinked_alert u WHERE u.run_id = :'run' GROUP BY 1, 2, 3 ORDER BY 1, 2;
ROLLBACK;
SQL
IU="$(grep -m1 '^INDEXER_USERNAME=' docker/.env | cut -d= -f2- | tr -d '\r')"
IP_="$(grep -m1 '^INDEXER_PASSWORD=' docker/.env | cut -d= -f2- | tr -d '\r' | sed -E 's/^"(.*)"$/\1/')"
printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$IU" "$IP_" | base64 -w0)" \
  | curl -s -m 30 --cacert "$CA" --resolve wazuh.indexer:9200:127.0.0.1 -H @- -H 'Content-Type: application/json' \
      "https://wazuh.indexer:9200/wazuh-alerts-*/_search" \
      -d '{"size":0,"track_total_hits":true,"query":{"bool":{"filter":[
            {"range":{"timestamp":{"gte":"'"$WIN_FROM"'","lte":"'"$WIN_TO"'"}}},
            {"term":{"rule.groups":"vuln-webapp"}}]}},
           "aggs":{"rule":{"terms":{"field":"rule.id","size":100},
                   "aggs":{"loc":{"terms":{"field":"location","size":10}},
                           "with_rid":{"filter":{"exists":{"field":"data.rid"}}}}}}}' \
  | jq -r '"indexer vuln-webapp alerts in window total=\(.hits.total.value)",
           (.aggregations.rule.buckets[] | "  rule.id=\(.key) count=\(.doc_count) with_data_rid=\(.with_rid.doc_count) locations=\([.loc.buckets[] | "\(.key):\(.doc_count)"] | join(","))")' \
  | tee -a "$OUT"
unset IU IP_

# (4-c) Suricata eve: 측정 창 안 앱 IP:8080 (app0) — 0 이면 NIDS 0건은 "관측 못 함"
APP_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "security-lab_app_net").IPAddress}}' target-web)"; echo "app_ip=$APP_IP" | tee -a "$OUT"
docker exec suricata cat /var/log/suricata/eve.json | python3 -I -c '
import sys, json, collections
app, s, t = sys.argv[1], sys.argv[2][:23], sys.argv[3][:23]
c = collections.Counter()
for l in sys.stdin.buffer.read().split(b"\n"):
    try: e = json.loads(l)
    except Exception: continue
    ts = e.get("timestamp", "")[:23]
    if not (s <= ts <= t): continue
    et = e.get("event_type")
    c["all " + str(et)] += 1
    if e.get("in_iface") == "app0" and e.get("dest_ip") == app and e.get("dest_port") == 8080 and et in ("http", "flow", "alert"):
        c["app0 " + app + ":8080 " + et] += 1
for k in sorted(c): print(f"  {k:<40} {c[k]}")
' "$APP_IP" "$WIN_FROM" "$WIN_TO" | tee -a "$OUT"

# (4-d) M14a·M14b·룰별 기록
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL' | tee -a "$OUT"
BEGIN READ ONLY;
SELECT a.definition_version, a.metric_id, a.endpoint, a.split_unit, a.x, a.n, round(a.p::numeric, 4) AS p,
       round(a.lo::numeric, 4) AS lo, round(a.hi::numeric, 4) AS wilson_hi, a.status
  FROM validation.v_metric_m14a a WHERE a.run_id = :'run' ORDER BY a.metric_id, a.endpoint;
SELECT b.definition_version, b.metric_id, p.label AS paired_label, b.paired_run_id, b.x, b.n, round(b.p::numeric, 4) AS p,
       round(b.hi::numeric, 4) AS wilson_hi, b.status
  FROM validation.v_metric_m14b b LEFT JOIN validation.measurement_run p ON p.run_id = b.paired_run_id
 WHERE b.run_id = :'run' ORDER BY b.metric_id;
SELECT x.sensor, x.rule_id, x.kind, x.alerts FROM validation.v_metric_m14_rule x WHERE x.run_id = :'run' ORDER BY x.sensor, x.kind, x.rule_id;
ROLLBACK;
SQL
```

판정 기준(멈출 것):
- (4-a) `CLOSED | VALID | 960/960/960` 이 아님
- (4-b) 미연결 앱 알림에 `/var/log/target/attack.json.log`(JSON 룰 100200대)가 있거나 `with_data_rid > 0` → rid 연결 실패 의심.
  2026-10-22 R2: 640건 전부 rule 100002·application.log·data.rid 0(레거시, B3 예상과 같음)
- (4-c) `app0 <APP_IP>:8080 http` 또는 `flow` = 0 → NIDS 0건은 "관측 못 함". R2: http 960
- (4-d) M14a 9행, APP_RULE·NIDS 6칸 `0/320` 이면 wilson_hi 0.0119(z²/(320+z²)), BACKEND_CORR 3칸 NO_RULE(n 은 320 유지, x·p NULL).
  M14b 짝 = S4-STACK-6-BASELINE, APP_RULE OK, NIDS NOT_COLLECTED(짝 run 이 R14 이전), **BACKEND_CORR NO_RULE(v1.9 — V8 이후)**,
  definition_version 은 V8 이후 'ADR-S4-01 v1.9'

## (4-V8) V8 적용 — M14b 비적용 상태 정렬(ADR-S4-01 v1.9, 스냅샷 전) **[STOP 2: 실행 전 승인]**

V7 의 M14b 는 BACKEND_CORR × 웹을 NOT_APPLICABLE 로 내어 M14a·M13(NO_RULE)과 어긋났다(2026-10-22 R2 (4) 확인). 스냅샷은 불변이라 저장 전에 맞춘다.
V8 은 v_metric_m14a(상수만 v1.9)·v_metric_m14b(상태 규칙)만 바꾼다 — ATTACK 쪽 뷰·함수·테이블·기존 스냅샷 무변경.
출력은 /tmp/s4-5-v8.log (나중에 증거 로그에 이어 붙임).

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2
V8LOG=/tmp/s4-5-v8.log
: > "$V8LOG"
# (0-V8) 적용 전 기준값 + 백업
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$V8LOG"
BEGIN READ ONLY;
SELECT f.installed_rank, f.version, f.success FROM validation.flyway_schema_history f ORDER BY f.installed_rank;
SELECT md5(string_agg(i.run_id || '|' || i.r10_status || '|' || coalesce(i.r10_reason, '-'), ',' ORDER BY i.run_id)) AS r10_md5,
       count(*) AS runs FROM validation.v_run_integrity i;
SELECT count(*) AS snapshot_rows FROM validation.metric_snapshot;
ROLLBACK;
SQL
B=~/capstone-backups/$(date +%F)_validation_pre-v8.sql
test -e "$B" && echo "EXISTS — 덮어쓰지 않음" | tee -a "$V8LOG" \
  || docker exec postgres sh -c 'pg_dump -U validation_rw -d "$POSTGRES_DB" -n validation --no-owner' > "$B"
ls -l "$B" | tee -a "$V8LOG"; sha256sum "$B" | tee -a "$V8LOG"

# (1-V8) 적용 — migrate 전용 진입점
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD' | tee -a "$V8LOG"

# (2-V8) 사후 확인 — r10_md5·runs·snapshot_rows 는 (0-V8) 과 같아야 한다
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL' | tee -a "$V8LOG"
BEGIN READ ONLY;
SELECT f.installed_rank, f.version, f.description, f.success FROM validation.flyway_schema_history f ORDER BY f.installed_rank;
SELECT md5(string_agg(i.run_id || '|' || i.r10_status || '|' || coalesce(i.r10_reason, '-'), ',' ORDER BY i.run_id)) AS r10_md5,
       count(*) AS runs FROM validation.v_run_integrity i;
SELECT count(*) AS snapshot_rows FROM validation.metric_snapshot;
SELECT b.metric_id, b.definition_version, b.status, b.x, b.n
  FROM validation.v_metric_m14b b JOIN validation.measurement_run r ON r.run_id = b.run_id
 WHERE r.label = 'S4-5-BENIGN-WEB-R2' ORDER BY b.metric_id;
SELECT a.status, a.definition_version, count(*)
  FROM validation.v_metric_m14a a JOIN validation.measurement_run r ON r.run_id = a.run_id
 WHERE r.label = 'S4-5-BENIGN-WEB-R2' GROUP BY 1, 2 ORDER BY 1;
ROLLBACK;
SQL
```

정상: `MIGRATE>> before=[1, …, 7] after=[1, …, 8]`, rank 8 `m14b status rule` success t; r10_md5·runs·snapshot_rows 가 (0-V8) 과 같음;
M14b `APP_RULE OK 0/360`·`BACKEND_CORR NO_RULE`·`NIDS NOT_COLLECTED`, 셋 다 v1.9; M14a `NO_RULE 3 / OK 6`, v1.9.
멈출 것: migrate 실패·after 에 8 없음, r10_md5·runs·snapshot_rows 변화, M14b BACKEND_CORR ≠ NO_RULE, APP_RULE 값이 (4) 와 다름.
그다음 (4) 를 다시 실행해 값 확인 → 스냅샷.

## (4-S) 스냅샷 **[STOP 3: (4) 재확인 후 실행 전 승인]**

두 겹으로 막는다: 직전 확인이 하나라도 어긋나면 스냅샷 SQL 을 실행하지 않고, 저장 직후 같은 트랜잭션의 검증(DO)이 어긋나면
예외 → COMMIT 전에 멈춰 롤백된다. psql 변수(`:'run'` 등)는 달러 인용(`$chk$ … $chk$`) 안에서 치환되지 않으므로
DO 앞에서 `set_config(…, true)`(트랜잭션 범위)로 넘기고 DO 안은 `current_setting` 으로 읽는다
(RunbookSnapshotSqlTest 가 이 블록을 그대로 실행해 확인 — 정상 COMMIT 12행, 기대 어긋남 → 예외·0행).
scope_kind: M14a = 'SCENARIO', M14b = 'ALL'(v_metric_m14a·m14b split_kind 를 take_benign_snapshot 이 그대로 복사).

```bash
cd ~/capstone-dev/mitre-attack-capstone-v2
LOG=detections/measurements/evidence/2026-10-22_s4-5-benign.log
SLOG=/tmp/s4-5-snap.log
: > "$SLOG"
RUN=3818e21a-bfa2-4c8d-9977-f89d8df35fc2
PAIR=b1c26be1-add2-4d45-8207-0998b0f743b1   # S4-STACK-6-BASELINE

# (4-S0) 스냅샷 직전 확인 (읽기 전용)
{ echo "## (4-S0) pre-snapshot $(date -u +%FT%TZ)"; git log --oneline -1; } | tee -a "$SLOG"
DIRTY=$(git status --porcelain | wc -l)
PRE=$(docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -F "|" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL'
SELECT i.status, i.r10_status, coalesce(i.r10_reason, '-'),
       (SELECT count(*) FROM validation.metric_snapshot s WHERE s.run_id = :'run'),
       (SELECT count(*) FROM validation.metric_snapshot s)
  FROM validation.v_run_integrity i WHERE i.run_id = :'run';
SQL
)
IFS='|' read -r ST R10 REASON RUN_SNAP TOTAL_BEFORE <<< "$PRE"
echo "dirty_files=$DIRTY status=$ST r10=$R10 reason=$REASON run_snapshot_rows=$RUN_SNAP total_snapshot_rows=$TOTAL_BEFORE" | tee -a "$SLOG"

if [ "$DIRTY" = "0" ] && [ "$ST" = "CLOSED" ] && [ "$R10" = "VALID" ] && [ "$RUN_SNAP" = "0" ] && [ "$TOTAL_BEFORE" = "178" ]; then
  docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN"' -v pair='"$PAIR"' -v before='"$TOTAL_BEFORE" <<'SQL' | tee -a "$SLOG"
BEGIN;
SELECT validation.take_metric_snapshot(:'run') AS inserted;
SELECT s.metric_id, s.scope_kind, s.scope_key, s.numerator, s.denominator,
       round(s.point_estimate::numeric, 4) AS p, round(s.ci_upper::numeric, 4) AS wilson_hi, s.status,
       s.definition_version, s.snapshot_rule_version, s.schema_version, p.label AS paired_label
  FROM validation.metric_snapshot s LEFT JOIN validation.measurement_run p ON p.run_id = s.paired_run_id
 WHERE s.run_id = :'run' ORDER BY s.metric_id, s.scope_key;
SELECT (SELECT count(*) FROM validation.metric_snapshot s WHERE s.run_id = :'run') AS run_rows,
       (SELECT count(*) FROM validation.metric_snapshot s) AS total_after, :'before'::bigint AS total_before;
-- psql 변수는 달러 인용 안에서 치환되지 않는다 → 트랜잭션 범위 설정으로 DO 에 넘긴다
SELECT set_config('chk.run', :'run', true) AS chk_run, set_config('chk.pair', :'pair', true) AS chk_pair,
       set_config('chk.before', :'before', true) AS chk_before;
DO $chk$
DECLARE
    v_run uuid := current_setting('chk.run')::uuid;
    v_pair uuid := current_setting('chk.pair')::uuid;
    v_before bigint := current_setting('chk.before')::bigint;
    v_rows int; v_a int; v_b int; v_paired int; v_def int; v_rule int; v_total bigint;
BEGIN
    SELECT count(*),
           count(*) FILTER (WHERE s.metric_id LIKE 'M14a\_%' AND s.scope_kind = 'SCENARIO'),
           count(*) FILTER (WHERE s.metric_id LIKE 'M14b\_%' AND s.scope_kind = 'ALL'),
           count(*) FILTER (WHERE s.metric_id LIKE 'M14b\_%' AND s.paired_run_id = v_pair),
           count(*) FILTER (WHERE s.definition_version = 'ADR-S4-01 v1.9'),
           count(*) FILTER (WHERE s.snapshot_rule_version = 'ADR-S4-01 v1.8')
      INTO v_rows, v_a, v_b, v_paired, v_def, v_rule
      FROM validation.metric_snapshot s WHERE s.run_id = v_run;
    SELECT count(*) INTO v_total FROM validation.metric_snapshot;
    IF v_rows <> 12 OR v_a <> 9 OR v_b <> 3 OR v_paired <> 3 OR v_def <> 12 OR v_rule <> 12
       OR v_total <> v_before + 12 THEN
        RAISE EXCEPTION 'snapshot check failed: rows=% m14a=% m14b=% paired=% def_v1.9=% rule_v1.8=% total=% (before % + 12) — ROLLBACK',
            v_rows, v_a, v_b, v_paired, v_def, v_rule, v_total, v_before;
    END IF;
END
$chk$;
COMMIT;
SQL
  { echo "## (4-S) end $(date -u +%FT%TZ)"; } | tee -a "$SLOG"
else
  echo "STOP: 스냅샷 직전 조건 불일치 — 실행하지 않음" | tee -a "$SLOG"
fi
```

정상: (4-S0) `dirty_files=0 status=CLOSED r10=VALID reason=- run_snapshot_rows=0 total_snapshot_rows=178` →
`inserted = 12`, 행 목록(M14a_APP_RULE·M14a_NIDS × SQLI·PATH_TRAVERSAL·SSRF `0/320` wilson_hi 0.0119 OK, M14a_BACKEND_CORR × 3 NO_RULE n 320,
M14b_APP_RULE `0/360` OK, M14b_BACKEND_CORR NO_RULE, M14b_NIDS NOT_COLLECTED, M14b paired S4-STACK-6-BASELINE, 전부 v1.9·rule v1.8),
`run_rows 12 | total_after 190 | total_before 178`, `DO`, `COMMIT`.
멈출 것: `STOP: 스냅샷 직전 조건 불일치`, `snapshot check failed`(롤백됨), 그 밖의 예외.

## (3-L) login 외부 전송 run S4-5-BENIGN-LOGIN (ADR-S4-01 v2.0 R17 f·R18 j)

- 성격: 전송을 코드가 하지 않는다 — 사람이 터미널 스크립트로 /api/auth/login 에 정상 로그인을 보내고(§T), 결과 CSV 만 ingest 한다.
  계정 user1·user2·user 순환(비밀번호는 파일·코드·로그·DB 에 없음 — 측정 시 `BENIGN_CRED_SEED_USER1`·`BENIGN_CRED_SEED_USER2`·`BENIGN_CRED_SEED_USER` 로 주입).
- 계획: `detections/corpus/benign/login-plan-v1.csv` (seq,credential_ref,username,scenario, 300행). 결과 CSV 열 = `seq,sent_at_ms,responded_at_ms,status`.
- 통제: APP_RULE 미적용(뷰 NOT_APPLICABLE), BACKEND_CORR(100231/100233 rid 링크 = FP, 100230/100232 기록만), NIDS(1000031/1000032 url+시각창 단일 후보).

### (1-V9) V9 적용 — login 엔드포인트 + M14 뷰 definition_version v2.0 **[STOP: 실행 전 승인]**

```bash
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD' | tee -a "$LOG"
```
정상: `before=[1, …, 8] after=[1, …, 9]`, rank 9 `benign login endpoint`. 그 뒤 읽기 확인: `benign_endpoint` 4행(login 포함), `v_metric_m14a`/`m14b` definition_version = `ADR-S4-01 v2.0`, 기존 run R10·스냅샷 수 불변.
멈출 것: after 에 9 없음, benign_endpoint 가 4행 아님, 기존 R10·스냅샷 수 변화.

### (2-L) open — OPEN BENIGN run 생성 **[STOP: 운영 DB 쓰기 — 실행 전 승인]**

git 작업 트리 깨끗·같은 label 없음 확인 후. 출력은 저장소 밖 `/tmp/s4-5-login-open.log`.
```bash
RUN_BENIGN_LOGIN=1 BENIGN_LOGIN_MODE=open BENIGN_LABEL='S4-5-BENIGN-LOGIN' \
LOGIN_PLAN_FILE='detections/corpus/benign/login-plan-v1.csv' \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.measure.BenignLoginRunIT' -i 2>&1 \
  | grep -E 'BENIGN>>|BenignLoginRunIT|FAILED|BUILD|필요 \(기본값 없음\)|깨끗하지|이미 있다' | tee /tmp/s4-5-login-open.log
```
정상: `BENIGN>> external open … expected=300`, `BENIGN>> login run_id=<UUID>`. 이 run_id 를 (4-L) ingest 에 쓴다. 멈출 것: `FAILED`, `이미 있다`, `깨끗하지`.

### (3-L-T) §T 사람 전송 (명령·비밀번호 기재 안 함)

- 현성이 별도 스크립트(`/tmp/s4-5-login.sh`, 저장소 밖)로 login-plan 순서대로 정상 로그인 전송, 비밀번호는 `BENIGN_CRED_*` 환경변수로만.
- 결과를 `/tmp/benign-login-result.csv` (열 `seq,sent_at_ms,responded_at_ms,status`)에 기록. seq 는 계획과 1:1, 전송 간격은 단일 후보 조건(다음 sent − 이전 응답 > 2×TOLERANCE=100 ms)을 지킨다.
- sandcat·Caldera 꺼짐은 (0)·(3-0) 과 같게 확인(측정 창 안 Caldera 헤더 없는 앱 로그 = 코퍼스 요청만).

### (4-L) ingest — 결과 CSV 적재·연결·close **[STOP: 운영 DB 쓰기 — 실행 전 승인]**

`RUN=<(2-L) run_id>`, CA 사본은 (3) 과 같음. 출력은 `/tmp/s4-5-login-ingest.log`.
```bash
RUN_BENIGN_LOGIN=1 BENIGN_LOGIN_MODE=ingest BENIGN_LOGIN_RUN_ID="$RUN" \
LOGIN_PLAN_FILE='detections/corpus/benign/login-plan-v1.csv' RESULT_CSV='/tmp/benign-login-result.csv' \
INDEXER_CA_FILE="$HOME/capstone-certs/wazuh-indexer-root-ca.pem" \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
INDEXER_USERNAME="$(grep -m1 '^INDEXER_USERNAME=' docker/.env | cut -d= -f2-)" \
INDEXER_PASSWORD="$(grep -m1 '^INDEXER_PASSWORD=' docker/.env | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/')" \
./gradlew cleanTest test --tests 'com.capstone.vuln.measure.BenignLoginRunIT' -i 2>&1 \
  | grep -E 'BENIGN>>|BenignLoginRunIT|FAILED|BUILD|§I|검색 상한' | tee /tmp/s4-5-login-ingest.log
```
정상: `BENIGN>> external ingest … rows=300`, `app log matched=300/300`, `R10={r10_status=VALID, … benign_loaded=300, benign_matched=300}`.
멈출 것: `§I 무결성 위반`(적재 0·run OPEN — CSV 고쳐 재시도), `matched ≠ 300`, `검색 상한`, `FAILED`, R10 ≠ VALID.

### (4-L 확인) R10·미연결·Suricata·M14 (읽기 전용, 출력 /tmp/s4-5-login-4.log)

(4) 와 같은 질의를 `RUN` 으로. 추가 판정 기준(멈출 것):
- 미연결 앱 알림에 JSON 룰(100200대 `/var/log/target/attack.json.log`)이 섞이거나 `with_data_rid` 가 BACKEND_CORR 연결 수와 안 맞음 → rid 연결 실패 의심
- 측정 창 Suricata `app0 <APP_IP>:8080 http`/`flow` = 0 → NIDS 0건은 "관측 못 함"
- M14a login 칸: APP_RULE = NOT_APPLICABLE, BACKEND_CORR·NIDS 는 `x/n`(FP 0 기대, n=300 이면 Wilson 상한 ≈ 0.0126), BACKEND_CORR x > 0 이면 FP 있음 — 원인 확인 전 스냅샷 금지

### (5-L) 스냅샷 **[STOP: (4-L) 재확인 후 실행 전 승인]**

(4-S) 와 같은 두 겹 방어로 `take_metric_snapshot(:'run')`. login run 은 definition_version `ADR-S4-01 v2.0`, M14a 3통제 × 1엔드포인트(login) + M14b 3통제 = 6행(스냅샷 행 수는 (4-L) M14 뷰 행으로 확인). snapshot_rule_version 은 `ADR-S4-01 v1.8`(take_benign_snapshot 불변).

## (5) 마무리

- /tmp 로그(s4-5-4·s4-5-v8·s4-5-snapshot·s4-5-login-*)를 증거 로그에 이어 붙이고 explicit pathspec 으로 커밋
- 잘못 찍은 스냅샷은 지우지 않는다 — `SELECT validation.withdraw_metric_snapshot('<run_id>', '<definition_version>', '<사유>');`
- login run 끝나면 S4-5 완료 조건(R17 e) 확인: WEB run·login run 둘 다 R10 VALID + 스냅샷
