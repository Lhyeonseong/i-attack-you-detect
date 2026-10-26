# S3 notes

## S3-1 결정 기록 (리뷰 요청)

1. **`MatchSource` 신설 (기존 `CorrelationSource` 미수정)**
   `correlation.CorrelationSource`(HEADER/UA_FALLBACK/NONE)는 이미 존재하고 AttackLogger 가 OCSF 로그
   `source` 로 직렬화하는 생산 계층 타입이다. RID 를 추가하면 생산 계층 수정이므로,
   소비 계층용 `MatchSource`(RID/HEADER/UA_FALLBACK/NONE)를 별도로 두었다.
   Correlation 의 필드명은 스펙대로 `correlationSource`. → 이름 변경 원하면 알려줄 것.
2. **패키지**: 스펙엔 "신규 패키지"지만 `com.capstone.vuln.correlation` 은 기존 패키지
   (Extractor/Info/Source). 같은 패키지에 새 파일만 추가했고 기존 3개 파일은 손대지 않음.
3. **Verdict 7상태**: Notion 용어집 기준 — SUCCEEDED_MISSED, SUCCEEDED_DETECTED, SUCCEEDED_BLOCKED,
   BLOCKED, FAILED_DETECTED, FAILED_UNSEEN, UNCERTAIN. enum 만 정의, 산출 규칙 없음.
4. **gtOutcome**: 스펙의 3값에 맞춰 `GroundTruthOutcome`(SUCCEEDED/FAILED/UNKNOWN) 신설.
   `AttackOutcome.EXECUTED` → 어디로 매핑할지(UNKNOWN 예상, 설계문서의 "EXECUTED→UNCERTAIN" 방침)는 엔진 슬라이스에서 결정.
5. **attackerVerdict**: Caldera fact 값이 SUCCEEDED/FAILED/EXECUTED/UNKNOWN 이라 기존 `attack.AttackOutcome` 재사용.
   `attackerMatch` 는 `Boolean`(공격자 판정 없으면 null).
6. **Correlation**: 식별자 final + 나머지는 엔진이 채우는 setter. `addLink()` 시 ConfidenceResolver 로
   bestConfidence/correlationSource 재산출. `observedUntil = attackTime + 30s`.
7. **ConfidenceResolver.source**: 값 동등비교 대신 임계 비교(≥1.0 RID, ≥0.9 HEADER, ≥0.7 UA_FALLBACK, 그 외 NONE).
8. 추가 테스트 `CorrelationTest` 1개 (observedUntil·초기 상태).

---

## S3-2 0단계 — 실제 입력 샘플 (2026-10-13 수집)

### 앱 OCSF 로그 — `docker exec target-web tail -n 3 /var/log/target/attack.json.log`
(호스트에 `/var/log/target` 없음 — named volume `target_logs` 라 컨테이너 안에서 읽음. 마지막 기록 10-11 BF 런)
```
{"time":1791725502103,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":6,"rid":"eb85e7c5-1723-4b0b-81cf-0e73af8a1908","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"POST","url":{"path":"/api/auth/login"},"user_agent":"Caldera/djlycn/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","args":"username=admin"},"http_response":{"code":401,"latency_ms":8,"body_length":60},"validation":{"outcome":"FAILED","evidence":[],"validator_version":"v1","technique_id":"T1110"},"correlation":{"op_id":"djlycn","ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","source":"HEADER"}}
{"time":1791725502131,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":6,"rid":"e18affb2-ccc0-4fd0-868f-ea13b4ee20a9","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"POST","url":{"path":"/api/auth/login"},"user_agent":"Caldera/djlycn/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","args":"username=admin"},"http_response":{"code":401,"latency_ms":3,"body_length":60},"validation":{"outcome":"FAILED","evidence":[],"validator_version":"v1","technique_id":"T1110"},"correlation":{"op_id":"djlycn","ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","source":"HEADER"}}
{"time":1791725502158,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":6,"rid":"b3391c90-a5d2-47aa-8931-f81b08fec452","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"POST","url":{"path":"/api/auth/login"},"user_agent":"Caldera/djlycn/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","args":"username=admin"},"http_response":{"code":401,"latency_ms":2,"body_length":60},"validation":{"outcome":"FAILED","evidence":[],"validator_version":"v1","technique_id":"T1110"},"correlation":{"op_id":"djlycn","ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","source":"HEADER"}}
```

### Wazuh alert — SSRF 100240
현재 `alerts.json` 은 오늘(10-13) 로테이션돼 100240 0건 → 아카이브 `2026/Oct/ossec-alerts-11.json`(10건)에서 1건:
```
{"timestamp":"2026-10-11T10:33:48.607+0000","rule":{"level":12,"description":"SSRF: internal/metadata target in url preview request (JSON, request-signal)","id":"100240","mitre":{"id":["T1190"],"tactic":["Initial Access"],"technique":["Exploit Public-Facing Application"]},"firedtimes":1,"mail":true,"groups":["vuln-webapp","attack-http-activity","ssrf","request_signal"]},"agent":{"id":"004","name":"wazuh.agent","ip":"172.19.0.3"},"manager":{"name":"wazuh.manager"},"id":"1791714828.6424","full_log":"{\"time\":1791714826898,\"metadata\":{\"version\":\"1.9.0\",\"log_name\":\"attack_http_activity\"},\"class_uid\":4002,\"class_name\":\"HTTP Activity\",\"activity_id\":3,\"rid\":\"77002c5b-3a9b-4ef8-8673-d7fe4b591756\",\"src_endpoint\":{\"ip\":\"172.20.0.1\"},\"http_request\":{\"http_method\":\"GET\",\"url\":{\"path\":\"/api/preview\"},\"user_agent\":\"curl/8.5.0\",\"args\":\"url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role\"},\"http_response\":{\"code\":200,\"latency_ms\":9,\"body_length\":40},\"validation\":{\"outcome\":\"SUCCEEDED\",\"evidence\":[{\"kind\":\"METADATA_REACHED\"}],\"validator_version\":\"v1\",\"technique_id\":\"T1190\"},\"correlation\":{\"op_id\":null,\"ability_id\":null,\"source\":\"NONE\"}}","decoder":{"name":"json"},"data":{"time":"1791714826898.000000","metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":"4002","class_name":"HTTP Activity","activity_id":"3","rid":"77002c5b-3a9b-4ef8-8673-d7fe4b591756","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/preview"},"user_agent":"curl/8.5.0","args":"url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role"},"http_response":{"code":"200","latency_ms":"9","body_length":"40"},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"METADATA_REACHED"}],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":"null","ability_id":"null","source":"NONE"}},"location":"/var/log/target/attack.json.log"}
```

### 필드 확인 결과 (지시와 다른 점은 실제 로그를 따름)
| 항목 | 지시 | 실제 |
|---|---|---|
| 공격시각 | time | `time` (epoch **ms**, number) |
| rid | metadata.uid? | **최상위 `rid`** (metadata 에는 version/log_name 만) |
| GT | validation.outcome | `validation.outcome` (SUCCEEDED/FAILED/… — EXECUTED 매핑은 파서 슬라이스) |
| correlation | .op/.ability/.source | `correlation.op_id` / `correlation.ability_id` / `correlation.source` |
| alert 시각 | timestamp | `timestamp` = `2026-10-11T10:33:48.607+0000` (콜론 없는 오프셋 → 파서에서 패턴 지정 필요) |
| rule.id | rule.id | `rule.id` (문자열), technique 은 `rule.mitre.id[]` (배열) |
| alert src ip | src_endpoint.ip | **`data.src_endpoint.ip`** (alert 최상위엔 없음. 앱 이벤트 전체가 `data.*` 에 실림) |
| alert rid/op | — | `data.rid`, `data.correlation.op_id` — null 이 **문자열 `"null"`** 로 옴 → 파서에서 null 처리 필요 |
| 엔드포인트 | — | `http_request.url.path` / `data.http_request.url.path` |
| searchableTime | — | alerts.json 에 없음(`@timestamp`=`timestamp`, S0 기록). indexer 조회 시점 측정값 → nullable 유지 |

## S3-2 결정 기록 (리뷰 요청)

1. **레코드 필드 추가 (실제 로그 기준)**: TIME_ONLY 의 "같은 엔드포인트" 판정을 위해 AttackEvent/AlertEvent 에
   `endpoint`(http_request.url.path) 추가. HEADER 와 UA_FALLBACK 구분을 위해 AlertEvent 에 `idSource`
   (기존 `CorrelationSource` 읽기 전용 재사용 — 로그의 `correlation.source`) 추가.
2. **alert 1건 → Correlation 1건 배정**: 후보 중 confidence 높은 것 → 관찰기간 내 우선 → attackTime 이 가장 가까운(늦은) 것.
   alertTime < attackTime 은 후보 아님.
3. **LATE**: 식별자 매칭(RID/HEADER/UA)인데 observedUntil 이후 도착 → 링크 기록 + lateDetection. 상한 없음.
   TIME_ONLY 는 정의상 시간창 안에서만 성립하므로 late 없음.
4. **BF 시퀀스 판정 = Wazuh 100231/100233 대체 (known-gaps.md Gap#1 해결 계획)**:
   `time` 기준 정렬 후 120s 창 내 FAILED ≥ 10 (임계 도달 시각 f) → f 이후 120s 내 SUCCEEDED 면 `bfSequence=true`.
   같은 ms 동률이면 FAILED 를 먼저 센다. 그룹 키는 지시대로 technique=T1110 + op_id + ability_id + srcIp
   (Gap#1 계획은 srcIp 만 — op 가 null 인 수동 재현도 (null,null,ip)로 묶임).
   그룹을 시간으로 쪼개진 않음(같은 op/ability/ip 면 한 그룹).
5. **BF 그룹의 Correlation**: attackTime = 가장 이른 이벤트, key.rid = 가장 이른 이벤트 rid(대표값),
   observedUntil = **마지막 이벤트 + 30s** (단건이면 attackTime + 30s 그대로). RID 매칭은 그룹 멤버 rid 전체로.
   gtOutcome: SUCCEEDED 1건↑ → SUCCEEDED / 전부 FAILED → FAILED / 그 외 UNKNOWN.
   Correlation 에 `lastAttackTime`, `eventCount`, `bfFailureCount`, `bfSequence` 필드 추가.
6. **TIME_ONLY 는 식별자 없는 alert 만**: rid·op_id 가 모두 null 인 alert 만 시간창 매칭 대상.
   다른 공격의 rid/op 를 가진 alert 는 시간·엔드포인트가 겹쳐도 링크하지 않음 (t3).

---

## S3-3 A-0 — Caldera 가 operation UUID 를 ability 에 줄 수 있는가 (2026-10-13 확인, 수정 없음)

- 이미지 `ghcr.io/mitre/caldera:latest` (컨테이너 `CITATION.cff` version 5.0.0 — 지시의 5.2.0 과 다름, 참고)
- 예약변수 전수 (소스 확인):
  - `app/objects/c_agent.py:76` Agent.RESERVED — `#{server} #{group} #{paw} #{location} #{exe_name} #{upstream_dest} #{payload:…}`
  - `app/objects/secondclass/c_link.py:98` Link.RESERVED — `#{origin_link_id}` (= **link** UUID, operation UUID 아님)
  - `app/objects/secondclass/c_executor.py:34` — `#{payload}`
- `#{operation_id}` 류 없음 → **경로 B 확정** (Caldera 파일 미수정).

### `/api/v2/operations` 실측 (헤더 `KEY`, red key)
- 응답: operation 배열. 각 op: `id`(UUID), `name`, `state`, `start`, `host_group[].paw`, `chain[]`
- `chain[]` 링크: `paw`, `ability.ability_id`, `ability.technique_id`, `decide`, `finish`, `agent_reported_time` — 초 단위 ISO(`2026-10-11T13:31:42Z`)
- **같은 paw(djlycn)가 2개 operation 에 모두 등장** (S2-VAL-RUN b08f0883 12:15~, S2-SSRF-validation-01 736ab6e7 13:28~),
  ability 도 같은 4종 → **paw → UUID 단순 테이블은 오답**.
- 앱 로그 djlycn 이벤트 16건의 `time` 이 전부 해당 op 링크의 `[decide, finish]` 안에 들어감
  (단 `finish` 가 초 절삭 — BF 마지막 이벤트 13:31:42.158 vs finish 13:31:42Z).

## S3-3 결정 기록 (리뷰 요청)

A1. **OperationResolver 해석 규칙**: (paw, ability_id, 이벤트 time) → 링크 `paw`·`ability_id` 일치 &&
    `decide ≤ time < finish + 1s`(초 절삭 보정, finish 없으면 진행중 → 상한 없음) 인 링크의 operation.
    후보 op 가 정확히 1개일 때만 resolved. 0개/2개↑·API 실패 → paw 유지 + `opIdResolved=false`.
    API 는 배치당 1회 조회.
A2. **매칭은 원본 paw 로**: alert 의 `correlation.op_id` 도 paw 이므로 HEADER/UA 매칭은 `agentPaw` 끼리 비교.
    UUID 는 라벨·집계용(`CorrelationKey.opId`). 3인자 `CorrelationKey(op, ability, rid)` = 로그 원본 키(opId=agentPaw=paw, 미해석).
A3. **설정 키는 코드 기본값으로만**: `application.yaml` 은 커밋 경로(correlation/) 밖이라 수정 안 함.
    `@Value` 기본값 — `app.caldera.api-url`(기본 `http://caldera:8888`), `app.caldera.api-key`(기본 빈값 → env `APP_CALDERA_APIKEY`),
    `app.correlation.late-alert-cap-seconds`(기본 0 = 비활성). → **yaml/.env 반영은 별도 커밋으로 할지 결정 필요.**
A4. **실측 검증**: 일회성 테스트(커밋 안 함, 삭제)로 실 Caldera API + 실 로그 djlycn 이벤트 28건 해석 →
    12:xx 14건 전부 b08f0883(S2-VAL-RUN), 13:xx 14건 전부 736ab6e7(S2-SSRF-validation-01), 전부 resolved=true.
    포트 닫힌 URL → WARN 로그 + paw fallback·opIdResolved=false 확인.

B1. **BF 그룹**: srcIp → (시간 분할) IP 구간 → username 별 → (다시 시간 분할) = Correlation 1건.
    즉 Correlation 단위 = srcIp + username + 시퀀스 구간. op/ability 는 라벨(성공 이벤트 것, 없으면 최빈값).
    HEADER/UA 매칭은 그룹 멤버 전체의 (paw, ability) 집합과 비교.
B1-spray. **스프레이 판정 위치**: IP 구간 단위로 "실패한 서로 다른 username 수 ≥ 5"(`SPRAY_ACCOUNT_THRESHOLD`)면
    그 구간의 모든 username Correlation 에 spray=true·sprayAccountCount=계정수. (계정별 시도 수 상한은 두지 않음)
    → ❓ 임계 5 는 테스트(5계정) 기준 잠정값. AN1277 기준으로 확정 필요. 스프레이를 계정별 N건이 아니라
       IP 단위 1건으로 집계할지도 Verdict/지표 슬라이스에서 결정 필요(현재는 계정별 N건 각각 플래그).
B2. **시간 분할 기준**: 마지막 실패(구간에 실패가 없으면 마지막 이벤트) 후 120s(`BF_TIMEFRAME`) 초과 공백.
    IP 구간 → username 구간 순으로 두 번 적용.
B3. **늦은 alert 상한**: `observedUntil + cap` 이후 alert 는 링크 안 함(=후보 아님). cap 은 관찰기간 이후 추가 허용 시간.
    `app.correlation.late-alert-cap-seconds` 기본 0 = 비활성. `new CorrelationEngine()` = 상한 없음.

---

## S3-4 Step 0 — 확인 결과 (2026-10-13, 코드 수정 없음) → 충돌 있어 정지

1. **validation.outcome → GroundTruthOutcome 매핑: 없음.** 로그 파서가 아직 없어 문자열 매핑 코드가 어디에도 없다.
   EXECUTED 는 처리 경로 자체가 없음(AttackEvent 는 이미 GroundTruthOutcome 으로 받음). → Step 1 신설 대상.
2. **BF DETECTED 판단: alert 링크 기반이지만 시퀀스 아님.** `CorrelationEngine.build()`(L226~235)가 관찰기간 내
   usable(≥0.7) 링크 1건↑이면 DETECTED — 시나리오 무관. `bfSequence` 는 앱 이벤트(GT) 시퀀스이며 탐지 판정엔 안 쓰임.
   → Step 2 의 "alert 기반 판정 추가, 앱 시퀀스는 묶기로만" 분기에 해당.
3. **AlertEvent 에 username 없음.** 실 alert 엔 있음: 100230 샘플 `data.http_request.args = "username=admin"`, `data.rid` 도 있음.
   현재는 alert→계정 귀속이 링크(RID 로 그 계정 Correlation 멤버 이벤트에 붙음)로만 간접 성립.
   DetectionLink 엔 ruleId·technique·alertTime·matchPath·confidence 만 있음(실패/성공 구분 필드 없음).
   (참고: 10-11 아카이브엔 100230 ×27, 100231 ×1, 100232 0건)
4. **SPRAY_ACCOUNT_THRESHOLD**: `CorrelationEngine.java:38` static 상수 5, 판정 L128, 세팅 L207~208(Correlation 에 spray·count).
   Correlation 에 "어느 IP 구간 소속인지" 식별자는 없음 → 캠페인 접기에 필드 추가 필요.
5. **MTTD·late 이미 있음** (Correlation 필드, CorrelationEngine L222~235):
   mttdMs = 관찰기간 내 최초 usable alert − attackTime / lateDetection = observedUntil 이후 링크가 하나라도 있으면 true /
   ingestionLagMs 도 계산. 단 "기준 충족 alert" 개념은 없음. t2·t4·t6 이 이 의미를 고정하고 있음.

### 질문 (답 받기 전 구현 안 함)
Q1. **늦은 alert 가 '기준 충족'이 되면 DETECTED 인가?** S3-2 규칙·t4 = "30s 이후 alert 는 DETECTED/MTTD 에 안 씀".
    Step 6 의 lateDetection = "기준 충족 alert time > observedUntil" 은 늦은 alert 로도 기준 충족이 가능하다는 뜻으로 읽힘.
    추천: (a) 판정은 관찰기간 내 alert 로만 → 늦게만 충족되면 NOT_DETECTED + lateDetection=true, mttd null (S3-2 와 일관).
Q2. **실패/성공 alert 구분 수단**: ruleId 뿐. 추천: Wazuh 100230=실패, 100232=성공을 상수(또는 설정)로 둔다.
    (연결된 앱 이벤트 GT 로 구분하면 B안 위반 — 탐지가 정답지 참조)
Q3. **AlertEvent.username 추가 여부**: 추천: 이번엔 추가 안 함 — Wazuh alert 는 항상 data.rid 가 있어 RID 링크로 계정 귀속됨.
    rid 없는 alert(Suricata)의 계정 귀속은 한계로 기록. (추가하려면 기존 10인자 생성자 유지 오버로드 필요 — 기존 테스트 수정 금지 때문)
Q4. **BF 기준에서 '성공 후 시퀀스'의 역할**: 추천: gt SUCCEEDED → 실패 ≥10(120s) 후 120s 내 성공 alert 까지 있어야 DETECTED
    (AN1276 = 100233 대체, Gap#1 의 핵심이 이 경보), mttd = 그 성공 alert 시각. gt FAILED → 실패 ≥10 이면 DETECTED, mttd = 10번째 실패 alert.
    대안: gt 무관하게 실패 ≥10 이면 DETECTED, 성공 후 시퀀스는 별도 플래그.
Q5. **탐지 상태·MTTD 이중화**: Correlation.detectionStatus/mttdMs(S3-2, 링크 기준, t2~t6 고정)는 그대로 두고,
    VerdictResult 에 판정 기준 detectionStatus/mttdMs/lateDetection 을 별도 산출해도 되는가. (추천: 예 — 기존 테스트 수정 금지라 덮어쓸 수 없음)

## S3-4 결정 기록 (Q1~Q5 답 반영, 2026-10-13)

- **탐지 상태 두 층 (Q5)**: `Correlation.detectionStatus/mttdMs/lateDetection` = 링크 기반 원시값(S3-2 의미, 디버깅·Gap 분석용, 그대로 유지).
  `VerdictResult.detectionStatus/mttdMs` = 시나리오 탐지 기준 판정값. **S4 지표는 VerdictResult 만 사용.**
- **결정4 (Q1)**: initialVerdict = alertTime ≤ observedUntil 인 링크만으로 판정 / verdict = 링크 전체(late-alert-cap 이내로 이미 걸러짐).
  lateDetection = 두 탐지 상태가 다름. mttdMs = 최종 기준 충족 alert − 단위 attackTime (늦어도 실제값).
  단위 observedUntil = 멤버 중 최대, attackTime = 멤버 중 최소.
- **실패/성공 alert (Q2)**: `VerdictEngine.BF_FAILURE_RULE_ID=100230`, `BF_SUCCESS_RULE_ID=100232` (vuln_rules.xml 출처). 정답지로 구분 안 함.
- **username (Q3)**: `AlertEvent.username` 추가(기존 10인자 생성자 유지), `AlertEvent.usernameFromArgs()` 로 `username=값` 파싱
  (파서 슬라이스에서 `data.http_request.args` 에 적용). DetectionLink 에 alert 자신의 srcIp·username 추가(기존 5인자 생성자 유지).
  **한계**: username 없는 alert(예: Suricata)는 BF/스프레이 계정 집계에서 제외 → 그런 계층만 탐지하면 BF 는 NOT_DETECTED (B4 테스트로 고정).
- **BF 기준 (Q4 대안)**: alert 자신의 (srcIp, username) 별, alert time 순(동률이면 실패 먼저), 120s 내 실패 ≥10 → DETECTED,
  mttd = 10번째 실패 alert. compromiseDetected = 그 뒤 120s 내 같은 계정 성공 alert (마지막 임계 도달 시각 기준). BF 단위가 아니면 null.
  계정 버킷이 여럿이면 기준 충족이 가장 이른 버킷을 채택.
- **스프레이 캠페인**: CorrelationEngine 이 BF 그룹에 `segmentId = srcIp#IP구간시작epochMs` 세팅(단건은 null).
  spray=true 인 Correlation 을 segmentId 로 묶어 SPRAY_CAMPAIGN 1건. 탐지 = 같은 srcIp 실패 alert 의 서로 다른 username 수 ≥ 임계,
  기준 시각 = 임계 번째 계정 alert. sprayAccountCount = 멤버의 값(앱 이벤트 기준 실패 계정 수). compromise 는 캠페인엔 null.
- **임계 설정값**: `app.correlation.spray-account-threshold`(기본 `CorrelationEngine.DEFAULT_SPRAY_ACCOUNT_THRESHOLD`=5, AN1277 잠정)
  — CorrelationConfig 가 CorrelationEngine(스프레이 플래그)과 VerdictEngine(캠페인 탐지)에 같은 값 주입. yaml 엔 아직 안 넣음.
- **공격자 판정 집계**: 멤버의 정규화 fact 중 null 은 제외하고 gt 와 같은 규칙. 전부 null → attackerVerdict=null(fact 누락).
  정규화 결과 타입은 `GroundTruthOutcome`(3값) 재사용.
- **memberCorrelationIds** = 각 Correlation 의 `key.rid`(가장 이른 이벤트 rid). Correlation 에 별도 id 필드는 아직 없음(DB 슬라이스에서).
- VerdictEngine 은 순수 함수 — `Correlation.verdict/attackerMatch` 필드는 채우지 않음(스프레이 멤버 이중 집계 방지와 일관).

---

## S3-5a Step 0 — 확인 결과 (2026-10-13, 코드 수정 없음) → 충돌 있어 정지

1. **실행 위치·DB**: 루트 Gradle 프로젝트 `vulnerable-webapp`(컨테이너 `target-web`) 안. DB 접근은 **JdbcTemplate**
   (VulnRepository·AuthController·ProductController). 초기화는 `spring.sql.init.mode=always` + `schema.sql`(users/products **DROP 후 CREATE**)
   + `data.sql`. 마이그레이션 도구 없음. 취약 앱 role = `vulnuser` = compose `POSTGRES_USER` → **`rolsuper = t` (슈퍼유저)**. PG 16.13.
2. **Testcontainers**: build.gradle 에 없음. Boot 3.5.13 BOM 관리 버전 testcontainers 1.21.4, flyway 11.7.2.
   compose postgres = `postgres:${POSTGRES_VERSION}`(=16), 컨테이너명 `postgres` → 로컬 `postgres:16`(641MB) 재사용 가능(새 pull 불필요).
   단 Testcontainers 기본값은 `testcontainers/ryuk` 이미지 pull 필요(로컬에 없음, 수 MB). Docker 29.1.3(min API 1.44) — 1.21.4 는 호환 버전.
   디스크 실측 78%(59G 중 44G 사용, 13G 여유).
3. **Correlation.verdict**: `CorrelationTest:21 assertNull(c.getVerdict())` 에서 사용 → 제거 불가, @Deprecated 대상.
   **attackerMatch**: 클래스 밖 사용처 없음 → 제거 대상.
4. **(S3-5b 참고) BF 성공 가능성**: `brute_force_auth.yml` 은 username **admin** 고정, 후보 `admin password 123456 Password1 admin123 qwerty test`.
   로그인은 평문 비교(`WHERE username=? AND password=?`)인데 admin 시드 비밀번호가 bcrypt 모양의 평문 문자열
   `$2a$10$abcdefghijklmnopqrstuv` → **후보 중 일치 없음 → Caldera BF 는 구조적으로 항상 FAILED**.
   SUCCEEDED 는 수동 재현(`user`/`password123`)으로만 가능.
5. **영속 id 없음**: Correlation 은 `key.rid`(가장 이른 이벤트 rid)만 대표값으로 가짐.

### 질문 (답 받기 전 구현 안 함)
Q1 ❗ **권한 분리(P7)가 실제로는 성립 불가**: 취약 앱 role 이 슈퍼유저라 `REVOKE` 가 무의미(슈퍼유저는 권한 검사 우회).
    부트스트랩 SQL 을 적용해도 취약 앱(=SQLi 로 탈취 가능한 접속)은 validation schema 를 읽고 쓸 수 있다.
    진짜 분리는 취약 앱을 비슈퍼유저 role 로 접속시키는 compose/.env 변경이 필요 → 이번 슬라이스 금지 범위.
    추천: (a) 이번엔 지시대로 SQL·코드 작성 + P7 은 테스트 컨테이너에서 "비슈퍼유저 취약 앱 role" 로 검증하되,
    **운영 현재 상태는 분리 미성립**을 known-gap 으로 기록하고 role 교체를 후속 슬라이스로.
    대안: (b) P7 보류 / (c) validation 을 별도 PG 인스턴스로(compose 변경 필요).
Q2 **Flyway 자동설정이 취약 DB 를 건드림**: flyway-core 가 클래스패스에 있으면 Boot 의 FlywayAutoConfiguration 이
    기본(취약 앱) datasource 에 대해 실행돼 `public.flyway_schema_history` 를 만든다(`spring.flyway.enabled` 기본 true).
    막으려면 application.yaml 에 `spring.flyway.enabled: false` 필요. validation 마이그레이션은 코드에서 Flyway API 로
    validation datasource 에만 실행. 추천: 이 한 줄은 **C1 에 포함**(C1 단독 상태도 안전하도록). 대안: C2 에 두고 C1~C2 사이 배포 금지.
Q3 **ryuk 이미지**: 추천 — build.gradle test 태스크에 `TESTCONTAINERS_RYUK_DISABLED=true` 환경변수(새 pull 없음,
    컨테이너 정리는 테스트 코드가 직접). 이건 "의존성 추가분" 밖의 build.gradle 변경. 대안: ryuk 소형 이미지 pull 허용.

### (질문 아님) 구현 시 처리 예정
- validation DataSource 는 `@Bean(defaultCandidate = false)` + @Qualifier 로 등록 → 취약 앱의 자동설정 DataSource 가 그대로 유지됨.
- `correlation.correlation_key` = 가장 이른 이벤트 rid(+시나리오), `verdict_result` 에는 업서트용 `unit_key`(SINGLE/BF=멤버 key, SPRAY=segmentId) UNIQUE 컬럼 추가 예정.
- `correlation.attacker_verdict` = 원본 AttackOutcome 4값 CHECK, `verdict_result.attacker_verdict` = 정규화 3값 CHECK.

## S3-5a 결정 기록 (Q1~Q3 답 반영, 2026-10-13)

- **권한 분리 (Q1-a)**: 부트스트랩 SQL 은 지시대로 작성(`db/bootstrap/validation_role.sql`, psql 변수 `valpw`·`app_role`(기본 vulnuser)).
  P7 은 테스트 컨테이너에 비슈퍼유저 `vulnapp` role 을 만들어 실제 psql 로 부트스트랩 2회 적용(재실행 안전성) 후 `permission denied` 확인.
  운영은 vulnuser 가 슈퍼유저라 미성립 → known-gaps.md **Gap #3** 기록.
- **Flyway (Q2)**: `spring.flyway.enabled: false` 는 C1 에 포함. validation 마이그레이션은 `ValidationSchemaMigrator` 가
  validation datasource 로만 실행(schemas/defaultSchema=validation, createSchemas=false — schema 는 부트스트랩이 만든다).
  `flyway_schema_history` 는 validation schema 안에 생긴다.
- **ryuk (Q3)**: pull 허용(testcontainers/ryuk:0.12.0, 29MB). 테스트 후 잔여 컨테이너 0 확인.
- **DataSource**: `validationDataSource` = `@Bean(defaultCandidate = false)` HikariCP(pool 2) — P8 에서 켜도 취약 앱 자동설정
  `dataSource` 빈이 그대로 있는 것까지 확인. 트랜잭션 매니저는 빈으로 등록하지 않음(VerdictRepository 내부 생성 — 앱 TM 영향 방지).
- **키 규칙**:
  - `correlation.correlation_key` = `Correlation.getCorrelationKey()` = 가장 이른 이벤트 rid, rid 없으면 `scenario|srcIp|attackTime(epoch ms)`.
  - `verdict_result.unit_key` = SINGLE/BF_SEQUENCE `unit:<correlation_key>`, SPRAY_CAMPAIGN `spray:<segmentId>` (VerdictResult 주석에도 명시).
  - VerdictResult.memberCorrelationIds 도 rid → correlationKey 로 통일(rid 있으면 동일 값).
- **upsert·이력**: correlation 은 correlation_key upsert + detection_link 전량 재작성. verdict_result 는 unit_key upsert,
  `initial_verdict` 는 최초 저장값 보존. 신규 저장 시 initial≠verdict 면 이력 1행(LATE_ALERT), 갱신 시 이전≠새 verdict 면 이력 1행
  (lateDetection 이면 LATE_ALERT, 아니면 RECOMPUTED). verdict_history 는 UPDATE/DELETE 트리거로 append-only.
- **CHECK**: correlation.attacker_verdict = 원본 4값(EXECUTED 포함), verdict_result.attacker_verdict = 정규화 3값.
  추가로 `ck_verdict_result_uncertain_consistency` (verdict=UNCERTAIN ⇔ uncertain_reason 있음).
- **alert_ref**: 컬럼만 있고 현재 NULL — AlertEvent 에 원본 alert id 가 없음. alert 파서 슬라이스에서 채울 것.
- **op_id**: 해석된 경우만 uuid 저장, 아니면 NULL(paw 는 `paw` 컬럼). 해석됐어도 UUID 형식이 아니면 NULL.
- **Correlation 필드**: `attackerMatch` 제거(사용처 없음), `verdict` 는 CorrelationTest 가 읽어서 @Deprecated("VerdictResult 사용").
- **알려진 한계**: 같은 correlation 이 재실행 때 다른 unit 으로 옮겨 가면(예: 스프레이 임계 변경) 이전 unit 의 verdict_member 행이 남는다.
  운영에서 임계 변경 시 run_id(S3-5b) 단위로 분리할 것.
