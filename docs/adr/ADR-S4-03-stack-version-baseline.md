# ADR-S4-03: 스택 버전 기준 (digest 고정 · 업그레이드 순서 · 회귀 기준)

- 상태: 채택 (Accepted)
- 버전: v1.3
- 작성일: 2026-10-20
- 결정자(DRI): 이현성
- 관련: ADR-S4-01(지표 정의, docs/adr/ADR-S4-01-metric-definitions.md), ADR-S4-02(validation-api, docs/adr/ADR-S4-02-validation-api.md)
- 근거 커밋: 1b1b5fb(스택 점검 기점), 00e4cb6(슬라이스 0R 증거)

## 1. 배경

S4 지표(ADR-S4-01)를 새 baseline으로 측정하기 전에 실행 환경의 버전을 점검했다(2026-10-20, 읽기 전용).
측정 대상 스택 일부가 공식 지원 범위를 벗어나 있었고, 모든 이미지가 태그로만 지정되어 있어
같은 compose 파일로 다시 띄워도 같은 소프트웨어가 올라온다는 보장이 없었다.

| 구성요소 | 현재 | 상태 |
|---|---|---|
| Spring Boot (target-web) | 3.5.13 | OSS 지원 2026-06-30 종료, 마지막 OSS 패치 3.5.16 |
| Suricata | 7.0.15 | 7.0 계열 EOL 2026-07-07. 8.0.7 릴리스에서 취약점 67건 수정 |
| Wazuh | 4.14.8 | 레지스트리 공식 4.14.8 태그와 동일(내부 리비전 표기 rc2). 4.14.9 출시됨 |
| Caldera | 5.2.0 (latest 태그) | 5.3.0 이미지는 레지스트리에 없음. CVE-2025-27364는 5.1.0 이상에서 수정되어 영향 없음 |
| PostgreSQL | 16.13 | 지원 중. 최신 마이너 16.15 |
| Temurin JDK 17 | 17.0.20.1 | 지원 중, 현재 최신 |
| mock-imds (python:3.12-slim) | 소실 → 0R에서 복구 | Python 3.12 보안 지원 2028-10까지 |
| backend / react-dashboard (1학기 서비스) | Boot 3.3.5 / nginx 1.27.5 | 지원 범위 밖, 측정 경로에 없음 |
| digest 고정 | 0개 | 공급망 무결성 미보장 |

## 2. 결정

### D1. 모든 이미지를 index digest로 고정한다
- 형식: `image: <이름>:<태그>@sha256:<index digest>`. 태그는 사람이 읽기 위해 남기고, 실제 기준은 digest다.
- index digest(여러 플랫폼을 묶은 목록의 digest)를 쓴다. 플랫폼별 하위 manifest digest는 쓰지 않는다.
- 값의 출처는 pull 후 `docker image inspect`의 RepoDigests로 한다.
- 빌드 이미지(target-web 등)는 Dockerfile의 FROM 줄에 같은 원칙을 적용한다.

### D2. 업그레이드 대상 버전
| 구성요소 | 목표 | 비고 |
|---|---|---|
| PostgreSQL | 16.15 | 같은 주 버전 마이너 교체 |
| Wazuh | 4.14.9 | 착수 전 릴리스 노트로 정식 릴리스 여부 확인 |
| Suricata | 8.0 계열 최신 패치 | 착수 시점의 최신 8.0.x |
| target-web | Spring Boot 4.1.x | ADR-S4-02 D1(validation-api Boot 4.1.x)과 같은 계열 |
| Caldera | 5.2.0 유지, digest 고정 | 5.3.0은 공식 이미지가 없어 보류 |
| mock-imds | python:3.12-slim 유지, digest 고정 | 0R에서 받은 index digest |

### D3. 슬라이스 순서 (작고 동작 변화가 없는 것부터)
| 순서 | 슬라이스 | 크기 | 동작 변화 | 상태 |
|---|---|---|---|---|
| 완료 | 0R mock-imds 복구 | 작음 | 복구(정의 변경 없음) | 완료 00e4cb6 |
| 1 | 1a 현재 이미지 digest 고정 | 작음 | 없음 | 완료 3550c67 |
| 2 | 4 Caldera digest 고정 | 작음 | 없음 | 완료 8b93151 |
| 3 | 1b PostgreSQL 16.15 | 작음 | 마이너 | 완료 233454f |
| 4 | 1c Wazuh 4.14.9 | 중간 | 패치 | 완료 bac71f8 |
| 4.1 | IFN target-web 인터페이스 이름 고정 | 작음 | 없음(캡처 대상 동일) | 완료 c978766 |
| 5 | 5 1학기 서비스 삭제 | 작음 | 측정 스택에서 제거 | 완료(S4-STACK-5-SMOKE) |
| 6 | 2 Suricata 8 | 큼 | 있음(HTTP 파서 교체) | 완료(S4-STACK-2-SMOKE) |
| 7 | 3 target-web Boot 4.1 | 큼 | 있음(프레임워크 주 버전) | 대기 |
| 7.1 | 재부팅 검증 실제 VM 재부팅 후 RUNBOOK (0-c)·사후 확인 | 작음 | 없음 | 대기 |
| 8 | 6 새 baseline 20회 | 중간 | 측정 | 대기 |

쉬운 것을 먼저 처리하고, 동작이 바뀌는 큰 슬라이스(Suricata, Boot)는 뒤에 두어
앞 슬라이스의 회귀 기준선을 안정된 상태에서 확보한다. 근거와 충돌 검사는 4절에 둔다.

### D4. 슬라이스마다 구성요소 하나만 바꾼다
- 한 슬라이스에서 두 구성요소를 동시에 올리지 않는다. 회귀가 생기면 원인을 하나로 좁힐 수 있게 하기 위함이다.
- 슬라이스마다 커밋 1개 이상과 증거 로그 1개를 남긴다(detections/measurements/evidence/).

### D5. 회귀 기준 (슬라이스 완료 조건)
- 공통: 스모크 run(공격 7 + 대조 1, S4-1b-SMOKE와 같은 구성)을 돌려 정답지(GT) 결과가 S4-1b-SMOKE와 같아야 한다.
  공격 7건은 GT SUCCEEDED, 대조 1건은 GT FAILED. 스모크 run 라벨은 `S4-STACK-<슬라이스>-SMOKE`로 하고 baseline에 포함하지 않는다.
- 탐지 판정(verdict)은 S4-1b-SMOKE와 비교해 달라진 항목을 증거 로그에 모두 기록한다. 달라졌다는 것만으로 실패가 아니다.
- 슬라이스 2(Suricata 8): Gap #2(인코딩 경로 탐색)와 Gap #7(SQLi `%27`)을 다시 확인한다.
  Suricata 8은 HTTP 파서가 libhtp-rs로 바뀌어 URI 정규화 동작이 달라질 수 있다. 결과는 Gap 문서에 갱신한다.
- 슬라이스 3(Boot 4.1): 공통 기준에 더해, 앱 공격 로그(attack.json.log)의 필드 구조가 업그레이드 전과 같은지 골든 테스트로 확인한다.
- 스모크 전 사전 조건: Caldera에 state가 running 또는 paused인 operation이 0개여야 한다. 아니면 측정하지 않는다.
- 기준을 통과하지 못하면 원인을 증거로 먼저 확인한다. 원인이 슬라이스가 바꾼 것(이미지·설정)이면 해당 슬라이스를 되돌린다(이전 digest로 복귀).
- 원인이 슬라이스 밖의 환경 상태로 증거 확인되면(예: 슬라이스 이미지 ID 동일 + 다른 원인의 원본 기록), 그 원인을 제거하고 다른 라벨(`<라벨>-R2`)로 1회만 재측정한다. 재측정도 통과하지 못하면 되돌린다.
- 실패한 run은 삭제하지 않고 DB와 증거 로그에 남긴다.

### D6. 측정 결과에 스택 버전을 남긴다
- 새 baseline(슬라이스 6)의 증거 로그에 모든 구성요소의 버전과 digest를 기록한다.
- 기존 S3-GATE(2026-10-16)는 업그레이드 전 스택의 결과로 그대로 둔다. 새 baseline과 직접 비교할 때는 설정 변경이 있었음을 함께 표시한다.

### D7. 1학기 서비스(backend, react-dashboard)는 develop-v2에서 삭제한다
- develop-v2의 compose 정의와 `docker/services/backend`·`docker/services/react-dashboard` 폴더를 삭제한다. 코드 원본은 main·팀원 브랜치와 develop-v2 git 이력에 남는다.
- 이유:
  - develop-v2는 2학기 신규 개발이다. ③ 판정 엔진은 target-web 프로젝트의 correlation·verdict·measure와 validation schema, S4-6 validation-api(신규)이고, ④ 대시보드는 S4 후반 신규다. 두 서비스는 아키텍처 그림에 없다.
  - 2026-10-17 결정: main 백엔드(com.example.securitylab)는 S3 모델과 7가지 불일치로 가져오지 않고 원칙만 참고한다(이미 develop-v2에 구현).
  - 두 서비스는 지원 종료 구성요소(Boot 3.3.5, nginx 1.27)다(OWASP Top 10:2025 A03). compose를 시스템 정의로 보고 그림과 일치시킨다(Detection-as-Code).
  - backend는 DB superuser(`POSTGRES_USER`)로 접속했다(S3-INFRA 기록) → 삭제로 최소 권한에 맞춘다. 외부 연결 지점 최소화(ISMS-P 강화기준, 2차).
- 1학기 담당 팀원(윤지현, 박서진, 서우석)에게는 삭제 후 일괄 공지한다(2026-10-21 DRI 결정: main·팀원 브랜치 무영향, 이미지 백업과 git 이력으로 되돌릴 수 있어 사전 공지 대신 사후 공지).
- v1.3 초안: 삭제 전 사전 공지 — "삭제 전에 1학기 담당 팀원(윤지현, 박서진, 서우석)에게 먼저 알린다."
- v1.2까지: compose profile로 분리 예정 — "compose profile로 측정 스택에서 빼서 기본 기동에 포함하지 않는다. 코드와 이미지는 삭제하지 않는다. 분리 전에 1학기 담당 팀원(윤지현, 박서진, 서우석)에게 먼저 알린다."

### D8. Spring Boot 4.1 회귀 실패 시 대안
- 슬라이스 3이 D5 기준을 통과하지 못하면 최소 조치로 Boot 3.5.16(마지막 OSS 패치)까지 올리고, 4.1 이전은 다시 계획한다.

### D9. 업그레이드·측정 사전 절차
1. 볼륨으로 보존하는 설정 디렉터리는 업그레이드 때 이미지 기본 파일과 해시를 비교하고, 다르면 키 이름 차이를 확인한 뒤 판단한다.
   근거: Wazuh 공식 Internal configuration 문서 — internal_options.conf는 업그레이드 때 덮어쓰는 파일, 사용자 변경은 local_internal_options.conf (확인). 사례: 1c agent Disconnected(bac71f8 증거 로그).
2. 측정 전 target-web 인터페이스↔서브넷 짝을 RUNBOOK (0-c)로 확인하고, 다르면 측정하지 않는다.
   근거: moby/moby#49935 — 이름 지정 없는 인터페이스 순서는 생성·재시작에 걸쳐 보장되지 않음 (확인). Kohavi·Tang·Xu(2020) — 모든 실험 전 신뢰 가드레일 (확인). 사례: Gap #4 재발(c978766).
3. 판정 기준을 새로 정할 때는 직전 baseline 데이터로 그 기준의 전제가 성립하는지 먼저 확인한다.
   근거: Kohavi·Tang·Xu(2020) — 지표와 가드레일은 사전에 정의 (확인). 사례: IFN 스모크 "atk0 1건 이상" 기준 오류(스모크 트래픽은 attack_net을 지나지 않음, 1b·1c도 0건) — D5 직전 스모크 동일 기준으로 판정.
4. 스택 변경이 끝난 뒤 새 baseline(슬라이스 6) 전에 실제 VM 재부팅 후 사후 확인을 한다.
   근거: IFN 재시작 내구성 시험은 docker start 경로만 재현함(해석).

## 3. 슬라이스 0R 결과 (2026-10-20, 커밋 00e4cb6)
- mock-imds: compose 정의는 남아 있었고 컨테이너와 이미지만 없었다. `--no-deps`로 그 서비스만 다시 띄웠고, 다른 9개 컨테이너의 시작 시각은 바뀌지 않았다.
- 소실 구간: 2026-10-18 10:05:33Z(마지막 정상 응답) ~ 15:13:00Z(첫 무응답). 원인은 확인할 수 없다(git 흔적 없음, Docker는 삭제 이력을 보관하지 않음).
- 기존 측정 영향: 없음. S3-GATE(10-16)와 S4-1b-SMOKE(10-18 10:03~10:06Z)는 모두 소실 구간 전이다.
- 복구 후 SSRF: 공격 요청 GT SUCCEEDED(METADATA_REACHED), 대조 요청 GT FAILED, Suricata http 1건, Wazuh rule 100240 1건.
- 고정값: `python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`

## 4. 근거 (세 렌즈 + 2026 근거)

원칙: 기술 결정(D1·D2)은 표준이 1순위이고 기업별은 충돌 검사만 한다. 진행 결정(D3~D8)은 기업별 실무가 1순위다.
표기: (확인)=1차 출처 원문, (2차)=2차 출처, (해석)=원문을 우리 상황에 적용한 추론.

| 결정 | 표준 | 기술별 | 기업별 | 2026 근거 |
|---|---|---|---|---|
| D1 digest 고정 | OWASP Top 10:2025 A03 소프트웨어 공급망 실패 | Docker 공식 "Pin base image versions": 태그는 가변, digest는 항상 같은 이미지 보장 (확인) | 기술 결정, 충돌 없음 | Gartner 2026 전략 기술 트렌드 "디지털 출처 증명": 소프트웨어 무결성 검증, SBOM·attestation 명시 (확인) |
| D2 PostgreSQL·Wazuh 패치 | PostgreSQL 버전 정책: 항상 현재 마이너 사용 권고 (확인) | 각 프로젝트 릴리스 노트 | 기술 결정, 충돌 없음 | FIRST 2026 취약점 전망: CVE 첫 5만 건 초과 예측, 중간 갱신 약 66,000건, 패치 처리 역량 계획 권고 (확인) |
| D2 Suricata 8 | Suricata 7.0 EOL 2026-07-07 (확인) | 업그레이드 가이드, libhtp-rs 전환, 8.0.7 취약점 67건 수정 (확인) | 기술 결정, 충돌 없음 | FIRST 권고에 IDS 탐지 시그니처 개발 명시 (확인) |
| D2 Boot 4.1 | Spring Boot 3.5.16이 마지막 OSS 릴리스, 4.0·4.1로 업그레이드 공지 (확인) | 4.0 마이그레이션 가이드, 영향 파일 6~10개 실측 | 기술 결정, 충돌 없음 | Spring 공식 블로그(2026-06-01): AI 기반 보안 보고 급증, 2026-03 보고 55건 → 4월 CVE 26건, 최신 패치 업그레이드 강력 권고 (확인) |
| D3 순서 | 진행 결정 | 크기 추정(파일 수, 재생성 컨테이너 수) | SK하이닉스 S-Cube: 원인을 찾으며 대책을 함께 내고 쉬운 것은 즉시 조치 (확인). 보조 기법: WSJF — 지연 비용에 위험 감소를 포함하고 작업 크기가 작을수록 우선 (확인, SAFe 공식). 방법론: Rik Higham "The MVP is dead. Long live the RAT."(2016)·Eric Ries 『The Lean Startup』(2011) — 가장 큰 가정을 가장 작은 실험으로 먼저 검증 (확인) → 위험 가정은 각 슬라이스 Step 0 읽기 전용 확인으로 먼저 줄이고, 큰 변경(Suricata 8·Boot 4.1)은 뒤에 둠 (해석). [v1.2 정정: v1.1의 토스 "위험도 높은 가정부터 검증"은 토스 원문이 아닌 일반 해설 글 인용이라 삭제] | DORA "Working in small batches": 작은 단위 작업은 전달 성과를 예측하는 역량이며 DORA AI Capabilities Model(2025)의 7개 역량 중 하나 (확인, Google Cloud 연구 프로그램) |
| D4 한 슬라이스 한 구성요소 | 진행 결정 | 슬라이스별 커밋·증거 로그 | S-Cube why-why 원인 분석을 적용: 원인을 하나로 좁힐 수 있게 변경을 나눔 (해석) | 진행 결정 / DORA "Working in small batches" (확인) |
| D5 회귀 기준 | MITRE ATT&CK Evaluations: 설정 변경(Configuration Change) 분리 표기 (확인). Microsoft ExP: 표본 비율 불일치(SRM)면 결과를 믿지 말고 원인을 파이프라인 단계별로 진단 (확인). | 정답지 동일성, 로그 골든 테스트 | S-Cube: 현장에서 Check·Action이 자주 생략된다고 지적 → Check 필수 (확인). 토스: 주지표 개선과 가드레일 무손상을 함께 확인 → 정답지 동일성을 가드레일로 둠 (확인). 토스: 실패 회피보다 실패 회복 → 원인 제거 후 재측정, 실패 기록 보존 (확인). | Gartner AEV 시장 정의(gartner.com Peer Insights): 공격 가능성에 대한 일관되고 지속적이며 자동화된 증거, 결과 활용처로 빈번한 통제 테스트 자동화·탐지와 대응 능력 개선 명시 (확인). Market Guide(2026-03-24) 본문은 유료라 미열람 |
| D6 버전 기록·새 baseline | MITRE ATT&CK Evaluations: 설정 변경 표기 (확인) | measurement_run과 증거 로그 | 토스: 변경 전에 기준선을 먼저 세우고 측정 도구를 붙여 배포 (확인) | Gartner "디지털 출처 증명" (확인) |
| D7 1학기 서비스 삭제 | ISMS-P 강화기준 외부 연결 지점 최소화 (2차) | OWASP Top 10:2025 A03 지원 종료 구성요소(Boot 3.3.5, nginx 1.27) (확인). Detection-as-Code: compose = 시스템 정의, 아키텍처 그림과 일치. 최소 권한: backend의 DB superuser 접속 제거. [v1.2까지: Docker Compose profiles — 지정한 profile일 때만 기동] | 토스: 최고 수준 정보 공유가 좋은 결정의 전제, 이해관계자에게 목적·리스크 계획 사전 공유 (확인). 토스: 위임된 일의 결정은 DRI가 내림 (확인). v1.3 운영: DRI 결정으로 사후 일괄 공지 — 사전 공유 원칙과 다르게 운영함. main·팀원 브랜치 무영향, 이미지 백업과 git 이력으로 되돌릴 수 있어 위험을 낮춤 (해석). | CTEM Discovery(노출면). 원문이 서비스 정지를 직접 처방하지 않음 (해석) |
| D8 Boot 실패 시 대안 | Spring 지원 정책 | 3.5.16 = 마지막 OSS 패치 (확인) | 토스: 리스크를 줄이려 보수안 적용, 실패 회피보다 실패 회복 (확인) | 진행 결정 |
| D9 사전 절차 | Kohavi 신뢰 가드레일 (확인) | Wazuh internal_options 문서, moby#49935 (확인) | S-Cube 정착(표준화)·Check 생략 지적 (확인) | 직접 처방 원문 없음, 근거로 쓰지 않음 |

## 5. 알려진 한계
- mock-imds 소실 원인은 확인할 수 없다. 재발은 D1(digest 고정)과 이후 RUNBOOK 규칙으로 막는다.
- Wazuh 로컬과 레지스트리 digest 일치는 앞 12자리까지만 확인했다. 전체 64자리 비교는 슬라이스 1c에서 pull 후 RepoDigests로 한다.
- Wazuh 4.14.8의 내부 표기가 rc2인 이유는 공식 문서로 확인하지 못했다. 공식 4.14.8 태그와 같다는 것만 확인했다.
- 1학기 서비스(Boot 3.3.5, nginx 1.27.5)는 지원 범위 밖이지만 측정 경로에 없어 이 ADR의 업그레이드 범위에서 뺀다(D7).
- Gartner AEV 시장 정의는 gartner.com에서 1차 확인했다. Market Guide 본문은 유료라 미열람이며 그 내용은 인용하지 않는다.
- Caldera 5.2.0 소스 확인: app/service/app_svc.py:112 resume_operations()가 server.py:95에서 서버 기동 시 호출되며, 끝나지 않은 operation을 다시 실행함(함수 본문 원문은 v1.2 증거 로그에 기록). 슬라이스 4 첫 스모크 INVALID의 메커니즘이며, RUNBOOK (0-b)가 대책이다.
- attack_net은 현재 스모크 경로(호스트 sandcat → 127.0.0.1:8080 → app_net)에서 쓰이지 않는다. 용도와 측정 경로를 슬라이스 6 전에 확인한다.

## 6. 출처
- Gartner, Top Strategic Technology Trends for 2026 보도자료(2025-10): Digital Provenance
- FIRST, 2026 Vulnerability Forecast(2026-02-11) 및 중간 갱신(2026-06)
- Spring 공식 블로그, "Spring and Security In The Times Of AI"(2026-06-01): https://spring.io/blog/2026/06/01/spring_and_security_in_the_times_of_ai/
- Spring 공식 블로그, Spring Boot 3.5.16 마지막 OSS 릴리스 공지(2026-06-25) 및 4.x 마이그레이션 가이드
- OISF Suricata EOL 정책·8.0 업그레이드 가이드, oss-security 8.0.7 공지(2026-09-19)
- PostgreSQL 버전 정책: https://www.postgresql.org/support/versioning/
- Docker 공식 문서 "Building best practices — Pin base image versions", "Use service profiles"
- 벨기에 CCB 권고, CVE-2025-27364(Caldera, 5.1.0 이상 수정)
- Python 공식 릴리스 공지(3.12 보안 지원 2028-10까지)
- OWASP Top 10:2025 A03
- MITRE ATT&CK Evaluations 방법론(Detection Categories, Configuration Change)
- Fabijan 외(KDD 2019), "Diagnosing Sample Ratio Mismatch in Online Controlled Experiments" 및 Microsoft ExP "Diagnosing SRM" — SRM 원인을 파이프라인 단계별로 진단
- Oh D.S. 외(SK hynix), "How SK hynix applies TRIZ to industry field problems", Acta Technica Napocensis 63(3S), 2020
- 토스 팀 문화(toss.im/tossfeed/article/toss-team-culture), 토스 데이터 분석 실험 사례(toss.tech/article/data-analyst-ab-test), 토스 1일 출시 사례(launching-product-in-one-day)
- Gartner, Market Guide for Adversarial Exposure Validation(2026-03-24) — 벤더 인용 (v1.1까지 사용, v1.2부터 근거로 쓰지 않음)
- Gartner Peer Insights, Adversarial Exposure Validation 시장 정의(2026-10-20 열람)

## 7. 변경 이력
| 버전 | 날짜 | 내용 |
|---|---|---|
| v1.0 | 2026-10-20 | 최초 작성. 0R 결과 반영 |
| v1.1 | 2026-10-20 | D5에 스모크 사전 조건(running/paused operation 0개)과 원인별 처리(슬라이스 원인=되돌림, 슬라이스 밖 원인=원인 제거 후 재측정 1회, 실패 run 보존) 추가. 근거: 슬라이스 4 첫 스모크 INVALID(커밋 8b93151) |
| v1.2 | 2026-10-21 | D3 근거 정정(토스 오기재 삭제, RAT·Lean Startup·WSJF·DORA), D4 DORA 추가, D5 Gartner AEV 정의 1차 승격, Caldera resume_operations 확인, 슬라이스 표에 상태·IFN·재부팅 검증 추가, D9 업그레이드·측정 사전 절차 신설, attack_net 확인 항목 추가. 결정 D1~D8 내용 변경 없음 |
| v1.3 | 2026-10-21 | D7을 "compose profile로 분리"에서 "develop-v2에서 삭제"로 개정(이유: develop-v2는 2학기 신규 개발이고 두 서비스는 아키텍처 그림에 없음, 2026-10-17 main 백엔드 미도입 결정, 지원 종료 구성요소, backend superuser 접속). 기존 문구는 "v1.2까지"로 D7에 보존. 슬라이스 표 5행을 "5 1학기 서비스 삭제 / 측정 스택에서 제거"로 갱신. 다른 결정 내용 변경 없음. 4절 D7 근거 행 갱신, 팀원 공지는 사후 일괄 공지로 변경(DRI) |
