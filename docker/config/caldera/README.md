# Caldera 시나리오 정본 (Source of Truth)

이 디렉터리는 본 프로젝트의 Caldera 공격 시나리오 **정본**이다.
**2026-10-11** 기준, 실행 중인 Caldera 컨테이너의 런타임 상태(`object_store`)를 YAML로 export 한 것이다.

- adversary 8개 (`adversaries/`) + ability 34개 (`abilities/`, tactic별 하위 디렉터리)
- Caldera 버전: 5.2.0

## 정본을 런타임으로 잡은 이유

diff 결과 아래 ability 4개가 `origin/caldera-ablity`(윤현식 커밋)보다 런타임이 **더 새 버전**이었다
(윤현식이 Caldera UI 등에서 수정했으나 git에 커밋하지 않은 변경으로 추정). 팀장 결정으로 **런타임을 정본**으로 채택해 export 했다.

| ability id | 이름 | 비고 |
|---|---|---|
| `7aa89a87` | Brute Force - Dictionary-Based Authentication | 런타임이 git보다 축약·수정됨 |
| `c4e8f2b1` | Path Traversal - Text System File Access (Tier 1) | payload·마커 변경 |
| `d5f9a3c2` | Path Traversal - Binary File Access (Tier 2) | payload·마커 변경 |
| `e3f1a9c7` | SQL Injection - Error-Based Probe (Step 1) | 단일 라인화·마커 변경 |

→ **윤현식 확인 예정.** 확인 후 두 소스를 일원화한다.

나머지 adversary 정의와 30개 ability는 `origin/caldera-ablity` 와 내용이 동일하다.

## export 방식

- 런타임 Caldera REST API(`/api/v2/adversaries`, `/api/v2/abilities`)에서 받은 객체를
  Caldera stockpile 파일 스키마(adversary YAML, ability atomic YAML)로 변환했다.
- `command` 문자열, `parsers`, `technique`, `atomic_ordering` 은 런타임과 **바이트 단위로 동일**함을 왕복 검증했다.
- Caldera 기본값으로 재생성되는 필드(`timeout: 60`, `buckets=[tactic]`, `delete_payload: true`)는
  파일에서 생략했다(로드 시 Caldera가 동일하게 채움).

## 변수·엔드포인트

- 공격 대상은 `http://#{target.url}` 변수로 참조한다. **기본값을 박지 않았다.**
  operation 실행 시 fact 로 `target.url` 을 공급해야 한다.
  - 호스트(VM)에서 도는 에이전트: `target.url = 127.0.0.1:8080`
  - 컨테이너 내부 에이전트: `target.url = target-web:8080`
- adversary [G] (OWASP XSS+SSRF)의 SSRF ability에 들어있는 하드코딩 엔드포인트
  (`127.0.0.1:9200`, `169.254.169.254` 등)는 런타임 그대로 유지했다.

## 로드 방식 (S2에서 bind-mount 확정)

Caldera 5.2.0 은 core data 로더가 `/usr/src/app/data/abilities`, `/usr/src/app/data/adversaries`
(플러그인 `data/` 와 **별도** 경로)에서도 YAML 을 읽는다. S2 에서 git 을 정본으로 못박기 위해
compose 에 다음 bind-mount 를 추가했다 (`docker/docker-compose.yml`, caldera 서비스):

```yaml
- ./config/caldera/abilities:/usr/src/app/data/abilities
- ./config/caldera/adversaries:/usr/src/app/data/adversaries
```

- stockpile builtin(162개)은 `plugins/stockpile/data/abilities` 에 있어 가려지지 않는다 (로딩 로그로 확인).
- caldera 재기동(`up -d --force-recreate caldera`) 시 git YAML 이 그대로 로드된다 = **git = source-of-truth**.

## S2 재작성 (DaC rewrite, 4종 + 신규 SSRF)

B1 범위로 다음을 재작성/신설했다 (나머지 30개는 pre-rewrite snapshot 으로 유지).

| 종류 | ability | id | 변경 |
|---|---|---|---|
| SSRF (신규) | `initial-access/ssrf_metadata_verdict.yml` | `a7f3c1d9…` | 신설. T1190(기존 T1090 Proxy 에서 상향). `/api/preview` + Mock IMDS(169.254.169.254). 공격자 verdict(`ssrf.verdict`/`ssrf.evidence.kind`) + DIFFERENTIAL 승격(결정2). |
| SQLi | `initial-access/sqli_error_probe.yml` | `e3f1a9c7…` | 응답 파싱 → `sqli.verdict` fact 추가(결정1). |
| Path Traversal | `discovery/path_traversal_tier1.yml` | `c4e8f2b1…` | `pt.verdict` fact 추가. |
| Path Traversal | `discovery/path_traversal_tier2.yml` | `d5f9a3c2…` | `pt.verdict` fact 추가(code/size 기반). |
| Brute Force | `credential-access/brute_force_auth.yml` | `7aa89a87…` | `bf.verdict` fact 추가. |

- 판정 산출: 각 ability 는 응답을 파싱해 **stdout 에 단일 JSON 한 줄**만 방출하고
  (`{"verdict":…,"evidence_kind":…}`), `plugins.stockpile.app.parsers.json` 로 fact 로 바꾼다.
  (Caldera json 파서는 stdout 전체를 `json.loads` 하므로 디버그 출력은 stdout 에 쓰지 않는다.)
  응답 본문·자격증명·파일 내용 원문은 fact 에 담지 않는다 (sentinel 도달/host-class/코드만).
- evidence_kind 는 webapp 측 ground-truth(`Evidence.EvidenceKind`)와 일치시켰다:
  SSRF=`METADATA_REACHED`, SQLi(error)=`RESPONSE_PATTERN`, PT=`FILE_DISCLOSED`, BF=`CREDENTIAL_VALID`.

### adversary

- `[V] ATT&CK Validation — Web` (`adv-attack-validation-web-001`): 4종 일괄.
  탐지 커버리지 T1190×3 (SQLi 100210 / PT 100220 / SSRF 100240) + T1110 (BF 100230~100233).
- per-technique 미니: `av_ssrf` / `av_sqli` / `av_path_traversal` / `av_brute_force`.

## 알려진 부채 (bind-mount 로 표면화된 pre-existing 결함, B1 범위 밖)

bind-mount 후 core 로더가 YAML 을 검증하면서 아래 snapshot ability 3건이 로드 실패한다
(이전에는 object_store 에만 있어 중복 제거되어 드러나지 않았음). **S2 범위 밖 — 별도 처리 필요:**

- `discovery/path_traversal_evasion.yml` ↔ `path_traversal_evasion_advanced.yml`:
  동일 id `55e6f7a8…` 중복 (tactic 불일치 → "wrong tactic").
- `initial-access/sqli_evasion.yml` ↔ `sqli_evasion_advanced.yml`:
  동일 id `44d5e6f7…` 중복.
- `initial-access/ssrf_internal_port_scan.yml` (`e2a3b4c5…`, T1046/discovery): "wrong tactic".

→ 재작성 4종·신규 SSRF·검증 adversary 는 모두 정상 로드됨을 확인(로그 무오류).
