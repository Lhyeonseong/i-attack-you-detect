# Known Detection Gaps

탐지 룰이 놓치는 것으로 확인된 경우를 기록한다. 여기 적힌 갭은 아직 룰/설정으로 고치지 않은 상태다.

---

## Gap #1 — BF 100231·100233: 고속 이벤트에서 analysisd 병렬 매칭으로 상관 미탐

| 항목 | 내용 |
|---|---|
| 룰 | Wazuh 100233 (`bf_success_after_failures`), 100231 (`bf_login_failures_same_ip`) — `detections/sigma/brute_force_login.yml` |
| ATT&CK | T1110 Brute Force / Detection Strategy DET0463 (Brute Force Authentication Failures with Multi-Platform Log Correlation) |
| 영향 | SUCCEEDED_MISSED — 앱 Validator는 AUTH_SUCCESS → SUCCEEDED(CREDENTIAL_VALID)로 기록하지만, "실패 반복 후 성공"(level 15) 경보가 나오지 않는다. 100231 미탐 시 "같은 IP 실패 반복"(level 12) 경보도 빠진다 |
| 확인 | 2026-10-11, 통합 스택 Wazuh manager 4.14.8 |
| 상태 | 미해결 — S3 Backend Correlation에서 처리 예정 |

### 증상

**(a) 100233** — 같은 IP에서 로그인 실패 10회 뒤 **약 15ms 안에** 성공 요청이 오면:

- 10번째 실패 → 100231 (level 12) 정상 발동
- 성공 → 100232 (level 12)만 발동, **100233 (level 15) 미발동**
- `alerts.json` 기록 순서가 100232 → 100231 로 뒤집혀 있다

**(b) 100231** — 같은 IP에서 로그인 실패가 **빠른 버스트**(예: 약 240ms에 10회)로 오면:

- 10건 모두 100230 (level 5)으로만 기록되고 **100231 (level 12) 미발동**
- frequency 상관(`frequency=10`, `if_matched_sid 100230`)이 병렬 매칭 중 임계 도달을 놓친다
  (10번째 실패가 평가될 때 앞선 100230 매칭이 아직 다 기록되지 않음)
- 100231이 없으므로 이어지는 성공도 100233이 될 수 없다

**결론** — Wazuh 내장 상관(`frequency`, `if_matched_sid`)은 고속 이벤트에서 전반적으로 신뢰할 수 없다.
이것이 상관 판정을 S3 Backend Correlation으로 옮기는 설계 결정의 근거다.

### 원인

`analysisd.rule_matching_threads=0`(CPU 수만큼 자동)이라 이벤트가 병렬로 룰 매칭된다.
100233은 `if_sid 100232` + `if_matched_sid 100231` 구조라서, 성공 이벤트가 평가되는 시점에
100231 매칭이 이미 기록돼 있어야 한다. 두 이벤트가 거의 동시에 도착하면 성공 이벤트가 먼저
평가되어 100231 이력을 찾지 못한다.
100231도 같은 원인이다: frequency 카운트는 이미 기록된 100230 매칭만 세므로, 실패 이벤트들이
동시에 매칭되면 어느 이벤트도 임계(10)에 도달한 것으로 보지 못한다.

단일 세션인 `wazuh-logtest`에서는 같은 시퀀스로 100233이 정상 발동한다 (순차 처리이기 때문).

### 재현

```bash
# 같은 IP에서 실패 10회 직후 바로 성공 → 100233 미발동
for i in $(seq 1 10); do
  curl -s -o /dev/null -X POST localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"user","password":"wrong'$i'"}'
done
curl -s -o /dev/null -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"user","password":"password123"}'
```

위 재현에서 실패 10회는 약 240ms 안에 끝나므로 (b) 100231 미탐도 함께 나올 수 있다 (타이밍에 따라 (a)만 나오기도 함).

대조군: 실패를 **0.3초 간격**으로 보내고, 100231 경보가 찍힌 것을 확인한 뒤 성공 요청을 보내면
100230 ×9 → 100231 → 100233 (level 15) 순으로 정상 발동한다.

### 해결 계획

- **S3 Backend Correlation**에서 처리: indexer에 저장된 단건 경보(100230 실패, 100232 성공)를 대상으로,
  같은 `src_endpoint.ip`에 대해 처리 순서가 아니라 이벤트 시각(`time`) 기준으로 상관한다.
  - 100231 대체: 120초 창 안의 100230 건수 ≥ 10
  - 100233 대체: 위 조건 충족 후 120초 안의 100232
- 하지 않는 것:
  - 100231·100233 룰 구조 변경
  - `analysisd.rule_matching_threads=1` (전체 처리량을 희생하므로 제외)

---

## Gap #2 — PT 인코딩 변형: Suricata 정규화 버퍼가 인코딩 룰을 무력화

| 항목 | 내용 |
|---|---|
| 룰 | Suricata 1000021~1000024 (`docker/config/suricata/local.rules`) |
| ATT&CK | T1190 Exploit Public-Facing Application / Detection Strategy DET0080 (multi-signal correlation: request → error → post-exploit process/egress) |
| 영향 | 네트워크 계층(Suricata)에 인코딩 변형 탐지 공백. 앱 로그 계층(Wazuh 100220)은 공백 없음 → 단일 계층에만 의존하면 미탐 가능 |
| 확인 | 2026-10-11, Suricata 7.0.15 / Wazuh manager 4.14.8 |
| 상태 | 미해결 — 계획만 (룰 변경 안 함) |

### 증상

- 인코딩 문자열을 매칭하는 룰 1000021(`%2e%2e%2f`), 1000022(`etc%2Fpasswd`), 1000023(`etc%2Fshadow`),
  1000024(`usr%2Fbin`)가 발동하지 않는다.
- 1000022는 이름이 "/etc/passwd access attempt"이지만 같은 이유로 평문 `/etc/passwd` 요청에도 발동하지 않는다.

### 원인

룰이 `http.uri` 버퍼를 검사하는데, `http.uri`는 **정규화 버퍼**라 퍼센트 인코딩이 디코딩된 상태다.
`%2e`, `%2F` 같은 인코딩 문자열이 버퍼에서 사라지므로 `content` 매칭이 원리적으로 불가능하다.
(원문 그대로의 URI는 `http.uri.raw` 버퍼에 있다.)

### 관측 결과

`/api/files/download` 에 변형 3종을 보낸 결과:

| 요청 (`filename=`) | HTTP | Suricata | Wazuh 100220 |
|---|---|---|---|
| a) `../../../../etc/passwd` | 200 | 1000020 | level 12 |
| b) `..%2f..%2f..%2fetc%2fpasswd` | 200 | 1000020 (디코딩되어 `../../` 로 매칭, 1000021 아님) | level 12 |
| c) `....//....//etc/passwd` | 404 | **없음** | level 12 |

- c)는 정규화 과정에서 `//` 가 합쳐져 연속된 `../../` 가 남지 않는 것으로 보인다.
- Wazuh 100220은 앱이 기록한 `http_request.args`(이미 디코딩된 값)에 정규식 `\.\./` 를 적용하므로 3종 모두 탐지한다.

### 표준 근거

- KISA 웹 취약점 점검 항목 FD(파일 다운로드)의 "인코딩 적용 우회"(URL 인코딩·더블 인코딩·유니코드 인코딩) 점검 관점
- ATT&CK DET0080 — T1190 탐지는 요청·에러·후속 행위 등 **다중 신호 상관**을 전제로 한다

### 해결 계획 (지금은 하지 않음)

- Suricata 룰을 `http.uri.raw` 버퍼로 바꾸거나, 정규화된 `http.uri` 에 맞게 디코딩된 문자열(`etc/passwd`, `../` 등)로 재작성
- 시점: S2 SSRF 작업에서 Suricata 룰을 손볼 때 함께 처리
- 또는 Verdict가 Suricata + Wazuh 다중 신호로 판정하면 단일 계층 공백이 자연스럽게 보완된다

(2026-10-21 슬라이스 2: Suricata 8.0.7(Rust libhtp)에서 같은 시험 요청 결과가 7.0.15와 동일 — 엔진이 아니라 룰 공백, 개선은 S5)

---

## Gap #3 — 취약 앱 DB role(vulnuser)이 superuser: validation 분리 무효 + SQLi 영향 범위 초과

| 항목 | 내용 |
|---|---|
| 대상 | compose `postgres` 의 `POSTGRES_USER`(=vulnuser) — 취약 앱(target-web)이 이 계정으로 접속 |
| 영향 | ① validation schema 의 `REVOKE` 가 무효 — 슈퍼유저는 권한 검사를 우회하므로 취약 앱 접속(=SQLi 로 탈취 가능한 접속)이 판정 데이터를 읽고 쓸 수 있다. ② SQLi 가 의도 범위(T1190 데이터 유출)를 넘어 `COPY ... TO PROGRAM` 등으로 DB 컨테이너 명령 실행까지 가능 |
| 확인 | 2026-10-13, `pg_roles.rolsuper = t` (PG 16.13) |
| 상태 | **해소 (2026-10-13, S3-INFRA)** — target-web 을 non-superuser role `vuln_app` 으로 교체 |

### 조치 (S3-INFRA)

- `db/bootstrap/app_role.sql` 로 `vuln_app` 생성(LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS),
  `public` 에 USAGE·CREATE, 앱이 기동마다 DROP/CREATE 하는 `users`·`products`(+소유 시퀀스·인덱스) 소유권을 `vuln_app` 으로 이전.
  서버 파일/프로그램 role(`pg_execute_server_program` 등) 소속 시 스크립트가 중단된다.
- `db/bootstrap/validation_role.sql` 을 `-v app_role=vuln_app` 으로 재실행해 validation schema REVOKE 적용.
- compose target-web: `SPRING_DATASOURCE_USERNAME=vuln_app`, 비밀번호 `${VULN_APP_DB_PASSWORD}`(기본값 없음).
  `POSTGRES_USER`(vulnuser)는 관리자 전용으로 남김. target-web → suricata 순으로 재생성.

### 검증 (운영 스택, 2026-10-13)

| # | 확인 | 결과 |
|---|---|---|
| — | target-web 접속 role (`pg_stat_activity`, target-web IP) | `vuln_app` ×10 (Hikari 풀), 기동 시 schema.sql DROP/CREATE 정상 |
| V1 | vuln_app `rolsuper` / validation schema 조회·생성 | `f` / `permission denied for schema validation` |
| V2 | vuln_app `COPY ... TO PROGRAM` / `pg_read_file` | `permission denied to COPY to or from an external program` / `permission denied for function pg_read_file`, role 소속 없음 |
| V3 | validation_rw validation 쓰기(롤백) / `public.users` 조회 | 쓰기 가능 / `permission denied for table users` |
| R1~R5 | 회귀 — 이전과 같은 payload | 검색 200, SQLi SUCCEEDED(RESPONSE_PATTERN)+100210, PT FILE_DISCLOSED+100220, BF 실패 FAILED+100230, SSRF METADATA_REACHED+100240 — 취약점·탐지 그대로 |

(`SET ROLE` 로 권한만 바꿔 확인 — 비밀번호 미사용)

### 남은 것

- `backend` 서비스는 여전히 `POSTGRES_USER`(superuser)로 접속 — 공격 대상은 아니지만 별도 role 분리 후보.
  (2026-10-21 슬라이스 5: backend 서비스를 develop-v2에서 삭제해 이 경로는 해소됨, ADR-S4-03 D7 v1.3)

---

## Gap #4 — Suricata 가 앱 트래픽을 못 봄: target-web 인터페이스 순서 변경 (`-i eth0` 고정)

| 항목 | 내용 |
|---|---|
| 대상 | `suricata` (`network_mode: service:target-web`, `-i eth0` 단일 인터페이스 캡처) |
| 영향 | 네트워크 계층 탐지 공백 — Suricata 룰(1000015·1000020·1000030 등)이 앱 HTTP 트래픽에 발동하지 않는다. Wazuh(앱 로그 계층)는 정상 |
| 확인 | 2026-10-13 S3-INFRA 재생성 후 R6 점검. eve.json 은 계속 갱신되지만 app_net(172.20.0.5) http/alert 이벤트는 **2026-10-10 이후 0건**, 이후엔 멀티캐스트·IMDS 트래픽만 |
| 상태 | 해결 (조치 2026-10-13 커밋 50b9625 → 2026-10-21 VM 재부팅 후 재발: compose priority가 컨테이너 설정에 남지 않아 docker start 때 순서 미적용 → 슬라이스 IFN에서 interface_name(app0·atk0·imds0·sec0)으로 재해결, docker start 재현 시험 2종 통과. 실제 VM 재부팅 검증은 슬라이스 6 직전 예정) |

### 원인

target-web 이 4개 네트워크(app_net·attack_net·imds_net·security_net)에 붙어 있고, 재생성 시 Docker 가 붙이는 순서에 따라
`ethN` 이 바뀐다. 현재 `eth0`=imds_net(169.254.169.2), `eth2`=app_net(호스트 공개 포트 트래픽), `eth3`=attack_net(Caldera).
S2 에서 imds_net 이 추가되고 재생성된 시점(10-11)부터 `eth0` 이 imds_net 이 된 것으로 보인다.
README 의 "eth0 이 보여야 한다" 확인은 인터페이스 존재만 보므로 이 상태를 잡지 못한다.

### 조치 후보 (당시 기록)

- compose 에서 target-web 네트워크별 인터페이스 이름/순서 고정 후 재생성
- Suricata 를 app_net·attack_net 인터페이스 모두 캡처하도록 변경
- 확인 절차에 "eth0 rx 패킷이 앱 요청과 함께 증가하는지" 추가

### 해결 기록

- 조치: 50b9625 (2026-10-13) — target-web 네트워크 순서 고정, Suricata app/attack/imds 캡처, README에 eve.json 실기록 점검 절차 추가. 변경 파일: `docker/docker-compose.yml`, `docker/README.md`
- 실관측 확인 (저장소 증거): eve.json(2026-06-01~) 2026-10-16 17~18시 UTC에 dest_ip 172.20.0.5(앱) HTTP 400건, IMDS(169.254.169.254) 40건 기록 → 앱 트래픽 관측 정상.
  증거 `detections/measurements/evidence/2026-10-20_s4-2-gap4-verify.log`
- 네트워크 탐지 동작 확인: 같은 시간대 PT(1000020)·BF(1000030~32)·SSRF(1000060) alert 발동 → 룰 엔진 정상
- 재발 위험: target-web 재생성 시 인터페이스 매핑과 eve.json 실기록 재확인 필요 (`docker/README.md` 67-73)
- 문서 갱신 지연: 해결 커밋이 known-gaps.md를 수정하지 않아 2026-10-20까지 "미해결"로 남아 있었음
- 교훈: 검증을 했다면 결과를 증거 로그로 커밋한다 (커밋 제목의 "verify"만으로는 증거가 아님)

### 재발·해결 기록 (2026-10-21, 슬라이스 IFN)

- 재발: 2026-10-21 VM 재부팅(디스크 확장) 후 `docker start` 로 올라온 target-web 의 연결 순서가 security→app→attack→imds 로 바뀜
  → eth0=security_net·eth1=app_net·eth2=attack_net·eth3=imds_net. Suricata(`-i eth0 -i eth1 -i eth2`)가 관리 평면을 캡처하고 imds_net 을 놓침.
  증거 `detections/measurements/evidence/2026-10-20_1c-wazuh-4.14.9.log` (3-10)·(3-11)
- 원인: 50b9625 는 compose `priority` 로만 연결 순서를 정했고, 이 값은 컨테이너 설정에 남지 않아(EndpointSettings GwPriority=0·DriverOpts=null)
  `docker start` 때 적용되지 않음. Docker 메인테이너 정리(moby/moby#49935)상 이름 지정 없는 인터페이스 순서는 생성·재시작에 걸쳐 보장되지 않음
- 임시 복구: compose `--force-recreate target-web suricata` 1회(1c (3-12)) → S4-STACK-1c-SMOKE 정상(1c (4-J))
- 해결: target-web `networks` 에 compose `interface_name`(app_net→app0, attack_net→atk0, imds_net→imds0, security_net→sec0, eth 접두사 금지 — Engine 28 릴리스 노트),
  Suricata `-i app0 -i atk0 -i imds0`. 스모크 전 확인 `detections/measurements/RUNBOOK-S4-1b-smoke.md` (0-c), 운영 규칙 `docker/README.md`.
  증거 `detections/measurements/evidence/2026-10-21_ifn-interface-names.log`
- 검증: 재생성(Step 2)·`docker stop/start` 내구성(Step 3)·스모크 S4-STACK-IFN-SMOKE(Step 4) — 결과는 위 증거 로그 (2-x)·(3-x)·(4-J)

---

## Gap #5 — 측정 truncate 범위 누락: verdict 없는 잔여 correlation 24행 (초안, S4-1)

| 항목 | 내용 |
|---|---|
| 대상 | 운영 `validation.correlation`·`detection_link` — S3 본측정(2026-10-16 17:00~18:07Z) 이전 시험 실행 잔여 |
| 영향 | `verdict_member` 로 어떤 verdict 에도 연결되지 않은 correlation 24행 + detection_link 41행. run 차원이 없어 어느 측정에도 귀속 불가. correlation 을 직접 집계하는 쿼리(M05 등)가 verdict 조인 없이 돌면 표본이 오염된다 |
| 확인 | 2026-10-18 S4-1 Step 0 (읽기 전용). 저장 배치 3개 × 8행: created_at 14:34:34Z(링크 5)·15:19:28Z(18)·15:22:59Z(18), attack_time 14:31:53Z~15:22:28Z, 시나리오 분포 SQLi 3·PT 9·SSRF 9·BF 3 (= 시험 op 3회 × 8) |
| 상태 | **보존 확정 (2026-10-18, DRI 이현성)** — 삭제·이동 금지. 백필 대상 아님(verdict 없음) |

### 원인

`MeasurementCampaign.run(n, truncate=true)` 의 `GateVerdictReader.truncateAll()` 이 `verdict_result`·`verdict_member`·
`verdict_history` 만 비우고 `correlation`·`detection_link` 는 남긴다. S3 본측정 전 시험 실행 3회의 verdict 는 지워졌지만
correlation 은 남았다. correlation 은 `correlation_key`(rid) upsert 라 이후 측정과 충돌하지는 않는다.

### 조치 후보 (미결정)

- S4-2 지표 뷰는 correlation 을 항상 `verdict_member → verdict_result(run_id)` 경유로만 읽는다(R1·R4 와 일치)
- correlation 에도 run_id 를 둘지 여부는 S4-4(Suricata 상관 입력) 설계 때 결정
- S4-1 부터 CampaignRunnerIT 의 truncate 는 기본 OFF (`MEASURE_TRUNCATE=1` 일 때만) — run 단위 집계로 truncate 필요 없음
- S4-1a 부터 CLOSED run 이 하나라도 있으면 truncate 자체를 거부(아무것도 지우지 않음)

---

## Gap #6 — OperationResolver 가 운영 측정 경로에 연결되지 않음: correlation.op_id 전부 NULL (S4-1 발견)

| 항목 | 내용 |
|---|---|
| 대상 | 측정 경로 CampaignRunnerIT → MeasurementCampaign → MeasurementHarness → CorrelationEngine |
| 영향 | S3 측정 correlation 184행 전부 `op_id NULL`·`op_id_resolved=false`. S3 DoD "op_id uuid" 는 단위 테스트(OperationResolverTest) 수준에서만 충족, 측정 경로에서는 미충족. op 단위 귀속이 불가해 S4-1 백필은 `decided_at`(save 트랜잭션 시각)으로 묶었다. 탐지 상관 자체는 영향 없음 — HEADER/UA 매칭은 원본 paw 로 성립(S3-3 A2) |
| 확인 | 2026-10-18 S4-1 Step 0·D-2 (읽기 전용) |
| 상태 | **해소** (S4-1b-SMOKE 스모크 통과, op=377ed11d-68b8-43ee-9928-fb223e9fb373, correlations 8/8 resolved, 2026-10-18) |

### 원인

- `OperationResolver` 는 빈 정의만 있고 운영 코드에서 호출하는 곳이 0곳 — `CorrelationConfig.java:35`
- 하네스가 resolve 없이 바로 상관한다 — `MeasurementHarness.java:49` `correlationEngine.correlate(window.attacks(), window.alerts())`
- `GtLogReader` 가 3인자 `CorrelationKey(paw, abilityId, rid)` 를 만들고, 이 생성자는 `opIdResolved=false` 고정 — `CorrelationKey.java:12`
- 호출 자체가 없어 실패 로그도 없었다. Caldera API·키는 정상(같은 키를 쓰는 attacker_verdict 는 160행 모두 채워짐)

### 조치 (S4-1b)

- 하네스가 `runOnce` 로 받은 Caldera operation UUID 를 op 창의 이벤트에 직접 연결 — 측정 경로의 권위 원천
- `OperationResolver`(paw + ability + 링크 시간창 추론)는 하네스 밖(수동 재현 등) fallback 으로 유지

구현(커밋 `19cf968`):
- `MeasurementHarness` 가 correlate 전에 op 범위 [attackTime, opFinish] 안 이벤트만 `OperationResolver` 로 해석하고,
  결과가 runOnce opId 와 **같을 때만** op_id 확정(두 독립 원천 교차검증). 불일치는 WARN 1줄 + 미해석(op_id NULL),
  Caldera 실패·범위 밖도 미해석 그대로, 측정은 계속. 판정 로직·resolver 알고리즘·스키마 무변경
- `MeasureConfig` 가 `CorrelationConfig` 의 resolver 빈을 하네스에 주입 — `MeasureConfigWiringTest` 로 배선 고정
- 측정 경로 통합 테스트(`MeasurementRunPersistenceTest`): 가짜 Caldera·가짜 앱 로그 → 저장된 correlation op_id = runOnce UUID
- 과거 S3 run(S3-GATE-dc66322) correlation 의 op_id 는 소급 수정하지 않음(이력 보존)

### 교훈

- 단위 테스트 통과 ≠ 운영 경로 연결. 컴포넌트 테스트가 green 이어도 호출 경로에 없으면 기능은 없는 것이다
- 통합 경로 테스트로 고정한다: 하네스 1회(가짜 Caldera) → 저장된 correlation 의 op_id 가 runOnce UUID 인지 단언

---

## Gap #7 — SQLi 오류 기반 절차 미탐 (100210 견고성 공백)

| 항목 | 내용 |
|---|---|
| 룰 | Wazuh 100210 — Sigma 원본 `detections/sigma/sqli_product_search.yml` |
| ATT&CK | T1190 Exploit Public-Facing Application / Detection Strategy DET0080 (multi-signal correlation) |
| 영향 | SUCCEEDED_MISSED — M03 SQLI 20/20 SUCCEEDED_MISSED, M02 SQLI 0/20, M06b TECHNIQUE 1/2 (T1190 일관 커버리지 깨짐) |
| 확인 | 2026-10-20, S4-2 baseline 첫 지표 (run `S3-GATE-dc66322`, ADR-S4-01 v1.4) |
| 상태 | 앱 로그 RESOLVED (Wazuh 100211 추가, 커밋 4668e71, 2026-10-22 S5 Before/After) · 네트워크(Suricata 1000013) OPEN |

### 증상

- 공격: Caldera ability `e3f1a9c7` "SQL Injection - Error-Based Probe (Step 1)", T1190,
  payload `keyword=%27` (작은따옴표 하나), adversary `attack_validation_web.yml` ([V])
- 정답지: SqliValidator `SQL_ERROR_EXPOSED` → SUCCEEDED (evidence `RESPONSE_PATTERN`)
  - 성공 수준: SQL 주입 가능성 입증 + 응답에 SQL 오류 노출. 데이터 탈취 아님 (OWASP WSTG-INPV-05)

### 관측 결과

원천 확인 (읽기 전용, Wazuh `ossec-alerts-16.json`, 2026-10-16 17~18시 UTC):

- 100210 = 0 / 대조군 100220 = 60, 100240 = 40 (Verdict와 1:1 일치) → 상관 누락 아님, 룰 미탐
- `products/search` 알림 100건 = 1002 ×20 (pipe 로그 잡음) + 86601 ×80 (Suricata의 Caldera 표식 탐지 4종:
  `X-Caldera-Ability`/`Op-Id`/`Technique` 헤더, User-Agent)
  - Suricata 86601 ×80은 같은 `/api/products/search` 요청의 Caldera 헤더·UA를 잡은 것
    → Suricata가 이 SQLi 요청을 실제로 관측했음 (캡처는 동작)
  - Caldera 표식 탐지는 테스트 도구 흔적이라 탐지로 인정하지 않음 (B안: 탐지는 테스트 표식과 독립)
- 네트워크 계층: Suricata SQLi 규칙(sid 1000013 `[SQLI] Single quote error probe in URI`)이 있으나 작은따옴표 단독 요청에 발동하지 않음
- Gap #4(캡처 공백)와 다름: 86601 발동으로 Suricata가 해당 요청을 관측했음이 확인됨. Gap #4 문서 상태 갱신은 별도 커밋으로 처리 예정. → 2026-10-20 Gap #4 해결 기록으로 반영함
- 네트워크 계층 실측 재확인 (eve.json, 2026-10-16 17~18시): Suricata가 앱 트래픽(172.20.0.5 HTTP 400건)을 캡처하고, 같은 시간대 PT·BF·SSRF alert는 발동했으나 SQLi sid(1000010~1000019)는 0건.
  → SQLi만 네트워크에서도 미탐. 캡처 공백 아님(Gap #4 해결 확인), 룰 공백. 증거 `2026-10-20_s4-2-gap4-verify.log`

**결론** — 앱 로그(Wazuh)·네트워크(Suricata) 두 계층 모두 SQLi 행위 탐지 0 (DET0080 다중 신호 관점의 공백).

### 원인 (해석)

100210 정규식이 `'...--` / `UNION` 등 특정 형태에 의존한다. S1에서 오탐(`laptop--pro`) 억제를 위해 좁힌 결과다.
→ 견고성 ↔ 정밀도 모순 (MITRE CTID Summiting the Pyramid: 특정 흔적 의존 분석은 저비용 변형에 회피됨)

- 네트워크 계층: Suricata sid 1000013은 정규화(디코딩)된 `http.uri` 버퍼에서 인코딩 문자열 `"%27"`을 찾음 → 디코딩 후에는 `'`로 바뀌어 원리상 매칭 불가.
  Gap #2(인코딩 규칙 1000021~1000024 미발동)와 같은 메커니즘. (규칙 원문 기준 해석, 재생 테스트는 S5에서)

### 해결 계획 (S5 H3, 지금은 하지 않음)

- Sigma 원본 먼저 수정 → Wazuh 룰 → 회귀 테스트 (정상 샘플 `laptop--pro`, `report.pdf` 포함)
- 단일 페이로드(작은따옴표)에만 맞춘 수정 금지 — 주입 행위를 잡도록
- 미탐률 M03가 주지표, 오탐률 M11이 가드레일
- After run은 `rules_digest`로 룰 변경(Configuration Change) 표기, Before(`S3-GATE`)는 보존
- Suricata 1000013: `http.uri.raw` 사용 또는 디코딩된 `'` 기준으로 수정 — Gap #2 조치와 함께 처리

### DRI 결정 대기 (S5 전, 현성)

- SQLi 시나리오에 데이터 추출 절차(예: `sqli_union_extract`) 추가 여부

### 증거

- `detections/measurements/evidence/2026-10-20_s4-2-sqli-source.log`
- `detections/measurements/evidence/2026-10-20_s4-2-v3v4-apply.log` (커밋 `b2e785c`)
- `detections/measurements/evidence/2026-10-22_s5-sqli-before-after.log` (S5 Before/After, 커밋 4668e71·2abc879)

### 조치·결과 (S5 Before/After, 2026-10-22)

- 앱 룰 **100211** 추가(요청 신호 확장, `http_request.args` 만, 커밋 4668e71). 100210 원문은 보존. 설계·사유 ADR-S5-01(요청→5xx 상관은 앱이 오류를 HTTP 200+본문으로 반환해 불가, 따라서 request-signal 로 한정).
- Before(S4-STACK-6-BASELINE + S4-5-BENIGN-WEB-R2) vs After(S5-SQLI-AFTER + S5-SQLI-AFTER-BENIGN-WEB), rules_digest 만 다름(wazuh), 같은 definition_version 행끼리 비교.
- **주지표 M03 SQLI (After−Before) Newcombe 95% = −1.000 [−1.000, −0.772] → 상한 < 0 PASS** (SUCCEEDED_MISSED 20/20 → 0/20).
- 가드레일1 M14a APP_RULE 엔드포인트별(search·download·preview) 0/320 → 하한 ≤ 0, FAIL 아님 PASS. 가드레일2 PT·BF·SSRF verdict·M09 Before와 동일. 가드레일3 rules_digest 변경(t).
- After SQLI ATTACK 링크 20건 전부 **APP_RULE 100211**(NIDS 0) — 룰 하나로 개선 입증(7-1c).
- 알려진 오탐 유형: 따옴표 포함 정상 검색어(`O'Reilly`·`it's`)는 100211 을 발동한다(logtest 확인). 이번 정상 코퍼스(홀드아웃)에는 그런 값이 없어 M14a 0/320. ADR-S5-01 가드레일1이 측정하는 유형이며 룰로 회피하지 않는다.
- **네트워크 계층(Suricata 1000013)은 여전히 OPEN** — 디코딩 버퍼에서 `'` 단독 미매칭(원인 동일). 다음 후보(ADR-S5-01 "하지 않는 것").

### 하지 않은 것

- 룰 수정, 앱 취약점 수정 (앱 SQLi는 의도된 시험 대상)

(2026-10-21 슬라이스 2: Suricata 8.0.7(Rust libhtp)에서 같은 시험 요청 결과가 7.0.15와 동일 — 엔진이 아니라 룰 공백, 개선은 S5)

---

## Gap #8 — metric_snapshot 불변 보장이 일반 DML 에 한정: 테이블 소유자가 validation_rw

| 항목 | 내용 |
|---|---|
| 대상 | validation.metric_snapshot·metric_snapshot_withdrawal (V5, ADR-S4-01 v1.6 R13 d) |
| 영향 | 소유자 role 은 `ALTER TABLE … DISABLE TRIGGER`(사용자 트리거 비활성화)·자기 권한 재GRANT 가 가능 → 스냅샷 수정·삭제를 막는 것은 일반 UPDATE·DELETE·TRUNCATE 뿐. 직접 INSERT 도 소유자 권한이라 함수 밖 값 기입을 막지 못함(INSERT 트리거는 VALID run 조건만 강제) |
| 확인 | 2026-10-21, S4-3 Step 0 (`detections/measurements/evidence/2026-10-21_s4-3-step0.log` 0-6): validation 스키마·테이블·뷰·함수 owner 전부 validation_rw, Flyway installed_by V1~V4 = validation_rw, validation_rw 는 superuser 아님 |
| 상태 | OPEN — role 분리(마이그레이션 소유 role ↔ 측정 쓰기 role ↔ 읽기 전용 role)는 별도 슬라이스 후보 |

### 근거

- (기술 1차) PostgreSQL 16 ALTER TABLE: `DISABLE TRIGGER` 는 테이블 소유자 권한, 사용자 트리거를 끌 수 있다
- (기술 1차) PostgreSQL 16 CREATE TRIGGER: TRUNCATE 는 문장 트리거로만 받는다 — V5 는 행 트리거(UPDATE·DELETE) + BEFORE TRUNCATE 문장 트리거 + REVOKE 를 함께 둔다
- 테스트로 확인한 것: validation_rw 의 UPDATE·DELETE·TRUNCATE → `permission denied`(REVOKE), superuser → 트리거 예외 (`MetricSnapshotTest` T3·T8)
- 소유자는 회수한 권한을 스스로 재부여할 수 있다 → 권한 층은 실수 방지 수준이고, 근본 해결은 role 분리
- run 삭제 (ADR-S4-01 R13 d): 스냅샷이 있는 run 은 삭제 불가(FK ON DELETE RESTRICT), 스냅샷이 없는 run 은 삭제 가능.
  FK 확인 쿼리(FOR KEY SHARE)는 참조 테이블 소유자 권한으로 실행되고(1차급: postgresql.org 메일링리스트 Tom Lane 답변 — FK 확인은 테이블 소유자 권한으로 실행, 문서 본문 명시 없음 + 실측)
  잠금 절은 최소 한 컬럼의 UPDATE 권한이 필요하므로(PostgreSQL 16 SELECT 문서 원문 'The use of FOR NO KEY UPDATE, FOR UPDATE,
  FOR SHARE or FOR KEY SHARE requires UPDATE privilege as well (for at least one column of each table so selected).')
  V5 는 run_id 컬럼 UPDATE 만 허용하고, 실제 수정은 트리거가 차단한다 (`MetricSnapshotTest` T11)
- 실측 원문 (2026-10-21, run_id 컬럼 UPDATE 허용 전 — 테이블 UPDATE 전부 회수 상태에서 superuser 연결의 `DELETE FROM validation.measurement_run`):
  `ERROR: permission denied for table metric_snapshot`
  `Where: SQL statement "SELECT 1 FROM ONLY "validation"."metric_snapshot" x WHERE $1 OPERATOR(pg_catalog.=) "run_id" FOR KEY SHARE OF x"`

### 해결 계획 (지금은 하지 않음)

- 스키마 소유 role(마이그레이션 전용)과 측정 쓰기 role 을 나누고, 쓰기 role 에는 metric_snapshot INSERT 를 주지 않고 함수(SECURITY DEFINER) EXECUTE 만 준다
- S4-6 읽기 전용 role 과 같이 설계(ADR-S4-01 v1.4 메모·ADR-S4-02)

---

## Gap #9 — Suricata eve.json 로테이트 미작동 (기록만)

| 항목 | 내용 |
|---|---|
| 대상 | suricata 컨테이너 `/var/log/suricata/eve.json` (volume suricata_logs) — S4-4 부터 NIDS 상관 입력(ADR-S4-01 v1.7 R14 b·c) |
| 증상 | `/etc/logrotate.d/suricata`(daily, rotate 3, postrotate `suricatasc -c reopen-log-files`)는 있으나 컨테이너에 cron·logrotate 프로세스가 없다 → 2026-06-01 이후 회전 없음. 디렉터리에 eve.json 하나뿐(회전 파일 없음) |
| 확인 | 2026-10-21 S4-4 Step 0 (`detections/measurements/evidence/2026-10-21_s4-4-step0.log` 0-3): eve.json 16270174 bytes, 23683줄, 첫 timestamp 2026-06-01T15:34:28Z, suricata.yaml rotate-interval 키 없음(NOK) |
| 영향 | 지금은 크기가 작고(16 MB) 측정 구간이 파일 안에 남아 있어 상관에 유리하다. 계속 커지면 하네스가 op 마다 전체 파일을 읽는 비용이 늘어난다(EveTelemetryReader 는 docker exec cat 전체 읽기). 회전이 생기면 측정 구간이 회전 파일로 넘어가 읽지 못할 수 있다 |
| 상태 | OPEN — 기록만. 회전·읽기 범위 정책은 별도 결정(측정 중 회전 금지 여부 포함) |

## Gap #10 — Wazuh 취약점 탐지 피드가 볼륨 10.85 GB 차지 (기록만)

| 항목 | 내용 |
|---|---|
| 대상 | volume `security-lab_wazuh_queue` (wazuh.manager `/var/ossec/queue`) |
| 증상 | `docker system df -v` 10.85 GB, 그중 `/var/ossec/queue/vd/feed` 11G (vulnerability detection 피드). 측정 로그와 무관 |
| 확인 | 2026-10-21 S4-4 Step 0 (`2026-10-21_s4-4-step0.log` 0-8): `df -h /` 99G 중 46G 사용(49%), 49G 여유 |
| 상태 | OPEN — 기록만. 디스크 여유가 줄면 취약점 탐지 모듈 비활성화 여부를 별도 결정 |

## Gap #11 — Wazuh 가 Suricata flow_id 를 실수 문자열로 저장: 2^53 초과 시 정밀도 손실 위험

| 항목 | 내용 |
|---|---|
| 대상 | 인덱서 wazuh-alerts-* rule.id 86601 의 `data.flow_id` — NIDS alert ↔ eve http 연결 키(ADR-S4-01 v1.7 R14 b) |
| 증상 | eve.json 에서는 정수(`578501012733101`)인 flow_id 가 Wazuh 에서는 `'578501012733101.000000'` 로 저장된다(실수 변환). 배정밀도 실수는 2^53(9007199254740992)보다 큰 정수를 정확히 담지 못하므로, 그런 flow_id 는 값이 바뀌어 eve http 와 연결되지 않는다 |
| 확인 | 2026-10-21 design-check 로그 C1·C2 (`detections/measurements/evidence/2026-10-21_s4-4-design-check.log`): S4-STACK-6-BASELINE 구간 2022건 전부 정수 문자열, 2^53 초과 0건, 연결 2022/2022. 구간 최대 flow_id 2247612882690626(< 2^53). Suricata 쪽 flow_id 상한은 확인하지 않았다 |
| 현재 처리 | 소수부가 0 이 아니면 연결하지 않고(AlertIndexReader.readNids), 연결 안 된 alert 는 orphan 으로 센다(nids_window_stat·v_nids_run_stat) — 정밀도 손실이 생기면 orphan 수로 드러난다. 스모크 기준 orphan 0 (RUNBOOK-S4-4-apply (4)) |
| 상태 | OPEN — orphan > 0 이 나오면 flow_id 값과 2^53 비교부터 확인. 대안 키(timestamp·src_port·url)는 아직 정하지 않았다 |

## Gap #12 — 공격 측정 경로의 인덱서 TLS 체인 미검증 (랩 전용, 127.0.0.1 바인딩)

| 항목 | 내용 |
|---|---|
| 대상 | measure 인덱서 질의(IndexerAlertSearchSource) — CampaignRunnerIT(공격 측정)·BenignRunIT(정상 코퍼스) |
| 배경 | 인덱서 인증서 SAN = DNS:wazuh.indexer 뿐, 측정은 https://127.0.0.1:9200 으로 접속 → 호스트명 검증은 항상 실패한다. S4-5 이전 구현은 JVM 전역 속성(jdk.internal.httpclient.disableHostnameVerification)에 기대어 호스트명 검증을 끄고 체인도 검증하지 않았다. 이 속성은 java.net.http 첫 사용 때 한 번만 읽혀, BenignRunIT 에서 정상 요청 클라이언트가 먼저 쓰이자 인덱서 질의가 SAN 불일치로 실패했다(2026-10-22 s4-5-benign 로그 (3-F), run dffb77a7) |
| 조치 (S4-5) | IndexerTls — X509ExtendedTrustManager 로 생성 순서와 무관하게 호스트명 검증만 생략. 인덱서 루트 CA(PEM)를 주면 체인은 검증한다. BenignRunIT 는 INDEXER_CA_FILE 필수(체인 검증) |
| 남은 공백 | CampaignRunnerIT(공격 측정)는 app.measure.indexer.ca-file 미설정이 기본 → 기존과 같은 trust-all(체인 미검증). 인덱서 포트는 127.0.0.1 바인딩(랩 전용) |
| 확인 (2026-10-22, 읽기 전용) | 호스트 루트 CA = docker/config/wazuh_indexer_ssl_certs/root-ca.pem(compose 가 인덱서 /usr/share/wazuh-indexer/config/certs/root-ca.pem 로 마운트) — 디렉터리 root:root 0500 이라 측정 사용자가 직접 읽지 못한다. 인덱서 서버 인증서는 이 CA 로 체인 검증 성공(openssl verify 0), IP 검사만 실패(64). CA sha256 지문 D4:6F:19:39:CF:B1:CA:F7:F4:04:7D:7F:5F:38:59:D1:18:13:6C:33:AC:E8:F0:52:67:D0:D6:C9:6F:B5:FD:F6. 인덱서 컨테이너 certs 디렉터리에 root-ca.key(CA 개인키)도 있다(기록만) |
| 상태 | OPEN — 공격 측정에도 CA 를 줄지(app.measure.indexer.ca-file)는 다음 공격 측정 RUNBOOK 에서 결정 |

---

## Gap #13 — SSRF CONTROL 과대평가: 공격자 판정이 정상(대조군) 요청을 성공으로 봄

| 항목 | 내용 |
|---|---|
| 대상 | SSRF 시나리오의 CONTROL(대조군) 요청 — 공격자 판정(attacker_verdict) vs 정답지(gt_outcome) |
| 증상 | S5-SQLI-SMOKE(run 4f51d307, 2026-10-22) 관찰: SSRF CONTROL 1건이 `attacker_verdict=SUCCEEDED`, `gt_outcome=FAILED`, `overestimate=true` — 공격자가 정상 URL(예: example.com)을 공격 성공으로 판정 |
| 영향 | 게이트(M09)는 ATTACK 시도만 보므로 S5-SQLI-SMOKE·AFTER 게이트는 PASS 유효(측정 결론에 영향 없음). 다만 공격자 판정 로직이 대조군을 성공으로 과대평가하는 경향 — 측정이 아니라 attacker 쪽 정의 문제 |
| 확인 | 2026-10-22 S5-SQLI 스모크 (`detections/measurements/evidence/2026-10-22_s5-sqli-before-after.log`) |
| 상태 | OPEN — 기록만. S5 범위 밖(SQLi 룰과 무관). 공격자 판정(대조군 처리) 재검토 후보 |

---

## Gap #14 — 가드레일(rules_digest)이 engine_version 을 보지 않음 (측정 후 발견)

| 항목 | 내용 |
|---|---|
| 대상 | Before/After 비교의 "한 변수" 가드레일3 = `measurement_run.rules_digest`(Wazuh·Suricata·Caldera 파일 해시). verdict_result.engine_version 은 포함하지 않는다 |
| 증상 | S5 Before/After 비교(2026-10-22)에서 engine_version 이 Before `s3-v1` vs After `s4-v1` 로 다름을 측정 후 발견. rules_digest 만 보는 가드레일3 은 이 차이를 잡지 못한다 |
| 영향 | 이번 SQLi 결론에는 영향 없음 — 근거: 7-1c(After SQLI 링크 20건 전부 APP_RULE 100211, 엔진 판정 경로 무관) + Gap #7(Before 는 앱·NIDS 모두 0 → 엔진 버전과 무관하게 미탐). 일반적으로는 엔진 변경이 "한 변수" 가정을 깰 수 있다 |
| 확인 | 2026-10-22 S5-SQLI (7-1b, `2026-10-22_s5-sqli-before-after.log`) |
| 상태 | OPEN — 기록만. 다음 Before/After 부터 가드레일3 에 engine_version 동일성 확인을 포함(RUNBOOK-S5-sqli 메모) |

---

## S0 측정 결론 (결정 기록)

갭이 아니라 S0 실측으로 확정한 결정을 기록한다. 측정일 2026-10-11, 통합 스택(Wazuh 4.14.8, Suricata 7.0.15).

### 1. 결정4 확정 — 관찰 기간 30초

- **관찰 기간 = 30초** (잠정 120초에서 변경)
- 근거: S0 실측 20회(request → searchable) p95 12.2s × 2 = 24.4s → 30s

| 구간 (ms, n=20) | p50 | p95 | max |
|---|---|---|---|
| 공격 → alert 생성 (agent + analysisd) | 688 | 967 | 981 |
| alert 생성 → indexer 검색 가능 (filebeat + refresh) | 10221 | 11812 | 11920 |
| **합계 (request → searchable)** | 10932 | **12213** | 12694 |

측정 방법: `?keyword=` SQLi(100210) 20회, 3~5초 간격. 요청마다 고유 마커를 넣고,
"alert 생성"은 문서의 `timestamp`(analysisd 생성 시각), "검색 가능"은 indexer를 100ms 간격으로
조회해 해당 문서가 처음 반환된 시각. 문서에는 색인 시각 필드가 없다(`@timestamp` = `timestamp`).

### 2. MTTD 정의

- **MTTD = 공격 시각 → analysisd alert 생성 시각** (alert의 `timestamp`)
- 수집 지연(alert → searchable)은 별도 지표 **Ingestion Lag** 로 분리한다.
  - 주원인: index `refresh_interval` 5s + filebeat backoff(기본 1s ~ 최대 10s)
- 이유: 파이프라인 버퍼링이 탐지 성능 지표를 오염시키지 않도록 지표를 분리한다.

### 3. 모드 확정 — 전 구간 탐지 전용(IDS)

- 현재 전 구간 탐지 전용(IDS), 차단 비활성 → **Verdict의 BLOCKED류는 확장 설계**. S0 실측으로 입증.
  - Suricata: AF_PACKET 3개 인터페이스(-i app0 -i atk0 -i imds0, compose interface_name으로 고정), `copy-mode: none`, 로그 "non-inline operation",
    로드된 64개 룰 전부 `alert` (`drop`/`reject` 0개) (2026-10-21 IFN에서 갱신, 이전 표기 -i eth0 단일은 50b9625 이후 사실과 달랐음)
  - Wazuh: manager·agent `ossec.conf` 의 `<active-response>` 블록 0개(기본 `<command>` 정의만 존재),
    manager `active-responses.log` 공란. agent 측 1줄은 공유 설정 변경에 따른 `restart.sh agent reload`(차단 아님)

### 4. 유보 — 파이프라인 튜닝

- index `refresh_interval`·filebeat backoff 튜닝은 S0(동결)에서 하지 않는다 → **S4 Metrics·Dashboard** 에서 재검토.
