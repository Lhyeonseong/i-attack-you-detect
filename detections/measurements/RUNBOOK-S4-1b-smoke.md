# RUNBOOK S4-1b — op_id 연결 스모크 측정 (n=1, label `S4-1b-SMOKE`) (실행: 이현성)

- 목적: Gap #6 조치 확인 — 측정 경로에서 correlation.op_id 가 Caldera operation UUID 로 기록되는지 (runOnce opId ∧ Caldera 링크 해석 일치)
- 성격: **실제 공격 1회**(Caldera operation 1개: SQLi·SSRF·PT·BF) + 운영 validation DB 쓰기(새 run 1개, verdict 8행)
- 위치: **저장소 루트**(`docker/.env` 가 있는 develop-v2 체크아웃, 커밋 `19cf968` 이상)
- 계정: DB 확인은 **`validation_rw`**(validation 스키마 소유, superuser 아님). 측정 JVM 도 `validation_rw` 로 접속(CampaignRunnerIT 고정)
- 비밀값: 명령에는 `$(grep … docker/.env)` 만 들어간다. Caldera 키는 `curl -H @-`(stdin)로 넘겨 프로세스 인자에도 남기지 않는다. 값을 `echo` 하지 말 것
  - `INDEXER_PASSWORD` 는 `.env` 에서 큰따옴표로 감싸져 있어 바깥 따옴표를 벗긴다(`sed`). 나머지 키는 따옴표 없음
- truncate: OFF(`MEASURE_TRUNCATE` 미지정). 지정하더라도 CLOSED run(S3 baseline)이 있으면 거부된다
- 어느 단계든 "멈출 것"이 나오면 다음 단계로 가지 말고 출력 그대로 공유
- 게이트 결과는 스모크 판정 대상이 아니다: n=1 이면 시나리오별 표본 < 20 → `INCONCLUSIVE` 가 정상

---

## (0) 사전 점검 (읽기 전용)

```bash
git log --oneline -1 && git status --porcelain | wc -l
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E '^(caldera|target-web|postgres|security-lab-wazuh\.(manager|indexer)-1)\b'
grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 5 -H @- http://127.0.0.1:8888/api/v2/agents \
  | jq -r '.[] | [.paw, .group, (.trusted|tostring), .last_seen] | @tsv'; date -u +%FT%TZ
docker exec postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -c "SELECT count(*) FROM validation.measurement_run WHERE label = '"'"'S4-1b-SMOKE'"'"'"'
```

정상 출력 예시:
```
<HEAD 해시> ...            ← 19cf968 이거나 그 이후
0                          ← 작업 트리 깨끗(아니면 git_dirty=true 로 기록됨 — 멈출 사유는 아님)
caldera	Up ...
target-web	Up ...
postgres	Up ... (healthy)
security-lab-wazuh.manager-1	Up ...
security-lab-wazuh.indexer-1	Up ...
<paw>	red	true	<지금으로부터 1분 이내>
<지금 UTC>
0                          ← 같은 label run 없음
```

멈출 것: 컨테이너 중 하나라도 없음, label 카운트 ≠ 0.
red 그룹 agent 가 없거나 `trusted=false`·`last_seen` 이 1분 넘게 지났으면 → (1) 로 agent 를 띄운 뒤 (0) 의 agent 조회를 다시 실행.
(2026-10-18 확인 시점: `mcukpa red false 2026-10-16T18:23:26Z` — 이틀 전 비콘, **(1) 필요**)
- R10이 INVALID면 run을 지우지 않는다. 원인을 제거한 뒤 재측정은 `<라벨>-R2`로 한다(ADR-S4-03 D5).

### (0-b) Caldera operation 확인 (읽기 전용)

state가 running 또는 paused인 operation이 0개여야 한다(ADR-S4-03 D5 사전 조건). 키는 `curl -H @-` 로 넘겨 출력되지 않는다.

```bash
grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 10 -H @- http://127.0.0.1:8888/api/v2/operations \
  | jq -r '"total=\(length)", (group_by(.state)[] | "\(.[0].state)=\(length)"),
           (.[] | select(.state == "running" or .state == "paused") | [.id, .name, .state, .start, ((.chain|length)|tostring) + " links"] | @tsv)'
```

정상 출력 예시:
```
total=<N>
finished=<N>                ← running= / paused= 줄이 없음
```

멈출 것: `running=` 또는 `paused=` 줄이 있음. 측정하지 말고, 함께 출력된 operation이 무엇인지 확인한 뒤 finished로 정리할지 결정한다(ADR-S4-03 D5).

### (0-c) Suricata 캡처 인터페이스 확인 (읽기 전용)

target-web 의 인터페이스 이름은 compose `interface_name`(app0·atk0·imds0·sec0)으로 고정되어 있다. 스모크 전에 이름↔서브넷 짝과
Suricata 캡처 대상을 확인한다(Gap #4 — 이름 없는 `ethN` 순서는 재부팅·`docker start` 때 바뀐 적이 있음).
suricata 는 target-web 네트워크 네임스페이스를 공유하므로 suricata 안에서 본 인터페이스 = target-web 인터페이스.

```bash
docker exec suricata sh -c 'for i in app0 atk0 imds0 sec0; do echo "$i $(ip -4 -o addr show dev $i 2>/dev/null | awk "{print \$4}")"; done; echo "eth_count=$(ls /sys/class/net | grep -c "^eth")"'
for n in app_net attack_net imds_net security_net; do docker network inspect security-lab_$n --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'; done
docker inspect -f '{{json .Config.Cmd}}' suricata
[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' suricata)" = "container:$(docker inspect -f '{{.Id}}' target-web)" ] && echo NM_OK || echo NM_MISMATCH
```

정상 출력 예시:
```
app0 172.20.0.3/16            ← security-lab_app_net 서브넷 안
atk0 172.18.0.3/16            ← security-lab_attack_net 서브넷 안
imds0 169.254.169.2/24        ← security-lab_imds_net 서브넷 안
sec0 172.19.0.5/16            ← security-lab_security_net 서브넷 안 (미캡처)
eth_count=0
security-lab_app_net 172.20.0.0/16
security-lab_attack_net 172.18.0.0/16
security-lab_imds_net 169.254.169.0/24
security-lab_security_net 172.19.0.0/16
["-i","app0","-i","atk0","-i","imds0","-k","none", …]
NM_OK
```

멈출 것(스모크 금지): 이름 뒤 주소가 비었음(인터페이스 없음), 주소가 짝 네트워크 서브넷 밖, `eth_count` ≠ 0,
suricata 명령의 `-i` 가 `app0`·`atk0`·`imds0` 이 아님, `NM_MISMATCH`(target-web 만 재생성됨 → `docker/README.md` 운영 규칙대로 suricata 재생성).

### (0-d) Suricata 실행 중 출력 설정 확인 (읽기 전용)

compose 명령줄 `--set` 은 suricata.yaml 의 목록 번호로 stats 출력을 끈다(번호는 이미지 기본 yaml 에 따라 다름 — 7.0 은 outputs.7·types.26, 8.0.7 은 outputs.5·types.32).
실행 중 프로세스 값(명령줄 `--set` 반영)을 unix 소켓 `conf-get` 으로 읽고, 번호가 아니라 **이름**으로 찾는다.
(`suricata --dump-config` 는 새 프로세스가 yaml 만 읽어 명령줄 `--set` 이 반영되지 않으므로 이 확인에 쓰지 않는다.)

`suricatasc` 출력 형식은 버전마다 다르다(7.0 `{"message": "no", "return": "OK"}`, 8.0.7 `{"message":"no","return":"OK"}` 공백 없음).
판독 함수 `g` 는 공백·순서와 무관하게 `"return":"OK"` 를 먼저 확인하고, 아니면 `MEASURE_FAIL` 을 출력한다.

```bash
docker exec -i suricata sh -s <<'EOF'
g(){
  out=$(suricatasc -c "conf-get $1" 2>/dev/null)
  echo "$out" | grep -Eq '"return" *: *"OK"' || { echo "MEASURE_FAIL conf-get $1"; return 1; }
  echo "$out" | sed -n 's/.*"message" *: *"\([^"]*\)".*/\1/p'
}
# 소켓 확인: outputs.0 은 항상 있어야 함
g outputs.0 >/dev/null || { g outputs.0; exit 1; }
# 목록 순회: 목록 끝의 NOK 는 순회 종료 조건으로만 쓰고 출력하지 않음
i=0; while n=$(g outputs.$i); do [ "$n" = stats ] && echo "outputs.$i stats enabled=$(g outputs.$i.stats.enabled)"; i=$((i+1)); done
i=0; while n=$(g outputs.1.eve-log.types.$i); do
  case $n in
    stats) echo "eve-log.types.$i stats enabled=$(g outputs.1.eve-log.types.$i.stats.enabled)";;
    alert|http|flow|files) e=$(g outputs.1.eve-log.types.$i.$n.enabled) || e="yes(미지정)"; echo "eve-log.types.$i $n enabled=$e";;
  esac
  i=$((i+1))
done
EOF
```

정상 출력 예시(8.0.7):
```
outputs.5 stats enabled=no
eve-log.types.0 alert enabled=yes(미지정)
eve-log.types.3 http enabled=yes(미지정)
eve-log.types.7 files enabled=yes(미지정)       ← fileinfo 이벤트를 만드는 type
eve-log.types.32 stats enabled=no
eve-log.types.33 flow enabled=yes(미지정)
```
(목록에 있고 `enabled` 키가 없으면 켜진 상태 — `yes(미지정)`)

(stats 의 `enabled` 는 명령줄 `--set` 으로 반드시 있어야 하는 키 → 없으면 `MEASURE_FAIL` 이 그대로 찍힘.
alert·http·files·flow 는 `enabled` 키가 없는 것이 기본이라 그 경우만 `yes(미지정)` 으로 본다.)

판정: 결과가 빈 문자열이거나 `MEASURE_FAIL` 이 한 줄이라도 나오면 (0-d) 실패(측정 실패 — 통과로 기록하지 않음).

멈출 것(스모크 금지): (0-d) 실패, `outputs.N stats enabled=no` 줄이 없거나 `no` 가 아님, `eve-log.types.N stats enabled=no` 줄이 없거나 `no` 가 아님,
alert·http·files·flow 중 하나라도 줄이 없거나 `enabled=no`.

---

## (1) Caldera agent 기동 (필요할 때만, 별도 tmux 창에서 켜 둔 채로)

```bash
./sandcat -server http://127.0.0.1:8888 -group red -v
```

- 플래그는 저장소 루트 `sandcat` 바이너리의 `-h` 출력으로 확인(`-server`, `-group`(기본 red), `-v`). 포트 8888 = `.env` `CALDERA_WEB_PORT`
- 이 창은 (2) 가 끝날 때까지 끄지 말 것. 다른 창에서 (0) 의 agent 조회를 다시 실행

정상 출력 예시(다른 창의 agent 조회):
```
<새 paw>	red	true	<지금으로부터 수 초 이내>
mcukpa	red	false	2026-10-16T18:23:26Z     ← 죽은 이전 agent 는 그대로 남아도 무방
```

멈출 것: 새 agent 줄이 30초 안에 나타나지 않음, sandcat 창에 연결 오류 반복.

---

## (2) 스모크 측정 실행 (n=1, 약 3~4분)

```bash
RUN_CALDERA_MEASURE=1 MEASURE_N=1 MEASURE_LABEL='S4-1b-SMOKE' \
APP_CALDERA_APIKEY="$(grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | cut -d= -f2-)" \
INDEXER_USERNAME="$(grep -m1 '^INDEXER_USERNAME=' docker/.env | cut -d= -f2-)" \
INDEXER_PASSWORD="$(grep -m1 '^INDEXER_PASSWORD=' docker/.env | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/')" \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.measure.CampaignRunnerIT' -i 2>&1 \
  | grep -E 'MEASURE>>|PER-RUN|  \[|GATE|RUN run_id|op_id 교차검증|Caldera operation 조회 실패|CampaignRunnerIT|FAILED|BUILD'
```

정상 출력 예시 (verdict·conf·mttd 값은 실행마다 다를 수 있음 — 행 수·구성이 요점):
```
CampaignRunnerIT > measure() STANDARD_OUT
    MEASURE>> starting campaign run label=S4-1b-SMOKE n=1 truncate=false
    PER-RUN op=<Caldera operation UUID> rows=8
      [SQLI/SINGLE] rid=... verdict=SUCCEEDED_MISSED ...
      [PATH_TRAVERSAL/SINGLE] rid=... (3줄)
      [SSRF/SINGLE] rid=... (3줄 — 그중 1줄이 대조군: gt=FAILED)
      [BRUTE_FORCE/BF_SEQUENCE] rid=... (1줄)
    GATE overall=INCONCLUSIVE totalSamples=7 totalUncertain=0 report=detections/measurements/gate-report-<iso>.md
      BRUTE_FORCE samples=1 ... -> INCONCLUSIVE   (시나리오 4줄 모두 INCONCLUSIVE)
    RUN run_id=<run UUID> R10=Result[status=VALID, reason=ATTACK 7, CONTROL 1 = expected]
    MEASURE>> done overall=INCONCLUSIVE totalSamples=7
BUILD SUCCESSFUL in ...
```

`PER-RUN op=` 의 UUID 를 (3)-(c) 비교용으로 적어 둘 것.

멈출 것: `op_id 교차검증 불일치` 또는 `Caldera operation 조회 실패` 줄이 보임, `rows=` 가 8 이 아님(0 이면 agent 미동작),
`R10=Result[status=INVALID…]`, `FAILED`, `MEASURE_LABEL 필요`, `measure() SKIPPED`(env 미주입).

끝나면 (1) 의 sandcat 창은 `Ctrl-C` 로 종료해도 된다.

---

## (3) 사후 확인 (읽기 전용 트랜잭션, validation_rw)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL'
BEGIN READ ONLY;
-- (a) 새 run
SELECT label, status, ended_at IS NOT NULL AS ended, git_commit, git_dirty,
       left(rules_digest->>'wazuh_rules', 12)       AS wazuh_rules,
       left(rules_digest->>'suricata_rules', 12)    AS suricata_rules,
       left(rules_digest->>'caldera_adversary', 12) AS adversary,
       (SELECT count(*) FROM jsonb_object_keys(rules_digest->'caldera_abilities')) AS abilities,
       expected_attempts, expected_controls
  FROM validation.measurement_run WHERE label = 'S4-1b-SMOKE';
-- (b) R10
SELECT r.label, count(*) FILTER (WHERE v.attempt_role = 'ATTACK') AS attack,
       count(*) FILTER (WHERE v.attempt_role = 'CONTROL') AS control,
       CASE WHEN r.expected_attempts = count(*) FILTER (WHERE v.attempt_role = 'ATTACK')
             AND r.expected_controls = count(*) FILTER (WHERE v.attempt_role = 'CONTROL') THEN 'VALID' ELSE 'INVALID' END AS r10
  FROM validation.measurement_run r JOIN validation.verdict_result v ON v.run_id = r.run_id
 WHERE r.label = 'S4-1b-SMOKE' GROUP BY r.run_id;
-- (c) 이 run 의 verdict 에 연결된 correlation 의 op_id
SELECT count(DISTINCT c.id) AS correlations, count(DISTINCT c.id) FILTER (WHERE c.op_id IS NOT NULL) AS op_id_not_null,
       bool_and(c.op_id_resolved) AS all_resolved, count(DISTINCT c.op_id) AS distinct_op_ids, min(c.op_id::text) AS op_id
  FROM validation.measurement_run r
  JOIN validation.verdict_result v ON v.run_id = r.run_id
  JOIN validation.verdict_member m ON m.verdict_id = v.id
  JOIN validation.correlation c ON c.id = m.correlation_id
 WHERE r.label = 'S4-1b-SMOKE';
-- (d) S3 baseline 불변
SELECT label, status, (SELECT count(*) FROM validation.verdict_result v WHERE v.run_id = r.run_id) AS verdicts
  FROM validation.measurement_run r WHERE r.run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727';
ROLLBACK;
SQL
```

정상 출력 예시:
```
    label    | status | ended | git_commit (40자) | git_dirty | wazuh_rules  | suricata_rules |  adversary   | abilities | expected_attempts | expected_controls
-------------+--------+-------+-------------------+-----------+--------------+----------------+--------------+-----------+-------------------+-------------------
 S4-1b-SMOKE | CLOSED | t     | <HEAD 해시>       | f         | 47715556fd0f | 007b188d4e80   | cba127e95e91 |         4 |                 7 |                 1

    label    | attack | control |  r10
-------------+--------+---------+-------
 S4-1b-SMOKE |      7 |       1 | VALID

 correlations | op_id_not_null | all_resolved | distinct_op_ids |        op_id
--------------+----------------+--------------+-----------------+----------------------
            8 |              8 | t            |               1 | <(2) 의 PER-RUN op= 와 같은 UUID>

      label      | status | verdicts
-----------------+--------+----------
 S3-GATE-dc66322 | CLOSED |      160
```

- `git_dirty` 는 `t`/`f` 중 하나면 된다(빈칸 = NULL 이면 멈출 것). (0) 에서 작업 트리가 깨끗했으면 `f`
- 룰 해시 3개는 2026-10-18 저장소 파일 기준값. 룰 파일을 바꾼 뒤라면 달라지는 게 정상(바꾼 적 없는데 다르면 멈출 것)
- 새 run 의 `rules_digest` 는 파일 해시 4종(`wazuh_rules`·`suricata_rules`·`caldera_adversary`·`caldera_abilities`)을 직접 담는다. `status` 키는 백필 run(`unverified`) 전용

멈출 것: (a) run 이 1행이 아님·`status ≠ CLOSED`·`git_dirty` 빈칸·expected ≠ 7/1, (b) `r10 = INVALID`,
(c) `op_id_not_null ≠ correlations`·`all_resolved ≠ t`·`distinct_op_ids ≠ 1`·op_id 가 PER-RUN 값과 다름, (d) `verdicts ≠ 160` 또는 행 없음.

### (3-c 보강) op_id 가 실제 Caldera operation 인지 Caldera API 로 확인

```bash
OP="$(docker exec postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -At -c "SELECT DISTINCT c.op_id FROM validation.measurement_run r JOIN validation.verdict_result v ON v.run_id = r.run_id JOIN validation.verdict_member m ON m.verdict_id = v.id JOIN validation.correlation c ON c.id = m.correlation_id WHERE r.label = '"'"'S4-1b-SMOKE'"'"'"')"; echo "db op_id=$OP"
grep -m1 '^APP_CALDERA_APIKEY=' docker/.env | sed 's/^APP_CALDERA_APIKEY=/KEY: /' \
  | curl -s -m 10 -H @- http://127.0.0.1:8888/api/v2/operations \
  | jq -r --arg op "$OP" '.[] | select(.id == $op) | [.id, .name, .state, .start] | @tsv'
```

정상 출력 예시:
```
db op_id=<UUID>
<같은 UUID>	S4-measure #1 <iso>	finished	<시작 시각 = (2) 실행 시각>
```

멈출 것: `db op_id=` 가 비었거나 2줄 이상, Caldera 조회 결과가 비어 있음(그런 operation 없음), name 이 `S4-measure #1 …` 이 아님.

### (3-d) Suricata 비교 — 직전 스모크와 같은지 (판정 기준, 읽기 전용)

직전 스모크 구간과 이번 구간을 아래 세 항목으로만 비교한다(ADR-S4-03 D5 "직전 스모크와 동일").
- (a) alert 수(sid별)
- (b) 공격 경로: dest_ip 가 target-web 현재 앱 IP 이고 dest_port 8080 인 flow·http 수
- (c) IMDS: dest_ip 169.254.169.254 인 http·flow 수

제외: IPv6 link-local·multicast(src 또는 dest 가 fe80::/10, ff00::/8), 그 밖에 (a)~(c)에 해당하지 않는 배경 이벤트.
in_iface 별 합계는 기록만 하고 판정에 쓰지 않는다(배경 멀티캐스트가 구간 경계에 따라 들어가거나 빠짐 — 슬라이스 5 스모크 사례).
앱 IP 는 측정 직전 inspect 로 읽는다(추측 금지 — 172.20.0.5 는 backend 였음).

```bash
APP_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "security-lab_app_net").IPAddress}}' target-web)"; echo "app_ip=$APP_IP"
# 구간: 직전 스모크 (2) start~end, 이번 (2) start~end (UTC, 증거 로그 값)
docker exec suricata cat /var/log/suricata/eve.json | python3 -I -c '
import sys, json, ipaddress, collections
app, W = sys.argv[1], {"prev": (sys.argv[2], sys.argv[3]), "this": (sys.argv[4], sys.argv[5])}
bg = lambda a: a and ":" in a and (ipaddress.ip_address(a) in ipaddress.ip_network("fe80::/10") or ipaddress.ip_address(a) in ipaddress.ip_network("ff00::/8"))
r = {k: collections.Counter() for k in W}
for l in sys.stdin.buffer.read().split(b"\n"):
    try: e = json.loads(l)
    except Exception: continue
    for k, (s, t) in W.items():
        if not (s <= e["timestamp"][:19] <= t): continue
        r[k]["iface:" + str(e.get("in_iface")) + " (기록만)"] += 1
        if bg(e.get("src_ip")) or bg(e.get("dest_ip")): continue
        et, d = e.get("event_type"), e.get("dest_ip")
        if et == "alert": r[k]["(a) sid " + str(e["alert"]["signature_id"])] += 1
        if et in ("flow", "http") and d == app and e.get("dest_port") == 8080: r[k]["(b) attack " + et] += 1
        if et in ("flow", "http") and d == "169.254.169.254": r[k]["(c) imds " + et] += 1
for key in sorted(set(r["prev"]) | set(r["this"])):
    p, q = r["prev"][key], r["this"][key]
    print(f"{key:<24} prev={p:<4} this={q:<4} " + ("same" if p == q else ("기록만" if "기록만" in key else "DIFF")))
' "$APP_IP" '<prev start YYYY-MM-DDTHH:MM:SS>' '<prev end>' '<this start>' '<this end>'
```

정상 출력 예시(슬라이스 5, prev=S4-STACK-IFN-SMOKE):
```
(a) sid 1000001          prev=20   this=20   same
…                                              (sid 9종, 합계 101)
(a) sid 1000060          prev=2    this=2    same
(b) attack flow          prev=7    this=7    same
(b) attack http          prev=20   this=20   same
(c) imds flow            prev=2    this=2    same
(c) imds http            prev=2    this=2    same
iface:app0 (기록만)      prev=163  this=162  기록만
iface:imds0 (기록만)     prev=7    this=6    기록만
```

멈출 것: (a)~(c) 중 `DIFF` 가 있음(통과로 기록하지 말고 차이 원문을 증거 로그에 남긴 뒤 DRI 판단), `app_ip=` 가 비었음.

---

## (4) 마무리

- (1) 의 sandcat 창 종료(`Ctrl-C`)
- (2) 가 만든 `detections/measurements/gate-report-<iso>.md/.json` 은 스모크 증거 — 보관할지 결정(커밋 시 explicit pathspec)
- (3) 전부 정상이면 `detections/known-gaps.md` Gap #6 상태를 "해소"로 변경(현성)
