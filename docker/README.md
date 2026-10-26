# Docker 통합 실행 가이드

이 Docker 구성은 단일 Docker Host에서 MITRE ATT&CK 기반 공격 시뮬레이션과 탐지 조회 흐름을 실행한다.

## 구성

- `caldera`: 공격 시뮬레이션
- `target-web`: 취약 Target Web, `/var/log/target/application.log` 파일 로그 생성
- `suricata`: Target Web 네트워크 네임스페이스에서 `eve.json` 생성
- `wazuh.agent`: Target Web 로그와 Suricata 로그 수집
- `wazuh.manager`: Agent 로그 처리 및 Indexer 전송
- `wazuh.indexer`: Wazuh alert 저장, OpenSearch API 제공
- `postgres`: Target Web용 PostgreSQL — Target Web 은 `vuln_app`(non-superuser)으로 접속, `vulnuser`(`POSTGRES_USER`)는 관리자 전용

1학기 서비스(`backend`, `react-dashboard`)는 develop-v2에서 삭제했다(ADR-S4-03 D7 v1.3). 원본은 main·팀원 브랜치에 있다.

## 실행

```bash
cd docker
cp .env.example .env
docker compose config
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d --build
docker compose ps
```

## 주요 포트

- Target Web: `http://localhost:8080`
- Wazuh Indexer: `https://localhost:9200`
- Caldera: `http://localhost:8888`

## 검증

```bash
curl -i http://localhost:8080/actuator/health
```

## 운영 규칙

- **target-web 재생성 시 suricata 재생성 필수** — suricata는 `network_mode: service:target-web` 으로
  target-web의 네트워크 네임스페이스를 공유한다. target-web만 재생성(`--force-recreate target-web`,
  이미지 재빌드 후 `up` 등)하면 suricata는 사라진 옛 네임스페이스에 남아 `lo`만 보이고 아무것도 캡처하지 못한다.

  ```bash
  docker compose -p security-lab up -d --no-deps --force-recreate target-web
  docker compose -p security-lab up -d --no-deps --force-recreate suricata
  # 1) 인터페이스 이름·서브넷 재확인: app0=app(172.20) / atk0=attack(172.18) / imds0=imds(169.254) / sec0=security(미캡처)
  docker compose -p security-lab exec suricata ip -br addr
  ```

  인터페이스 이름은 compose `interface_name`(target-web `networks`)으로 고정되어 재부팅·`docker start` 후에도 유지되고,
  suricata 는 이름으로 캡처한다(`-i app0 -i atk0 -i imds0`). 확인 방법은 `detections/measurements/RUNBOOK-S4-1b-smoke.md` (0-c).
  이름·서브넷 짝이 다르면 측정하지 않는다 (`detections/known-gaps.md` Gap #4 — 이전 `priority` 순서 고정은 `docker start` 때 적용되지 않았음).

  **통과 기준** — suricata 재생성 여부·`eve.json` mtime 갱신만으로는 통과가 아니다.
  재생성 후 `eve.json` 에 아래가 **실제로** 찍혀야 통과:
  - app_net(`172.20.x`) 출발지/목적지 HTTP 이벤트
  - IMDS(`169.254.169.254`) 목적지 이벤트 (SSRF egress)

- **DB 계정 분리** — Target Web 은 `vuln_app`(non-superuser)으로만 접속한다. `vulnuser`(`POSTGRES_USER`)는
  superuser 라 DB 관리자 전용(부트스트랩 SQL 실행)으로만 쓰고 앱 접속에 쓰지 않는다 (Gap #3).

## DB role 부트스트랩

새 스택이거나 role 비밀번호를 바꿀 때, **target-web 재생성 전에** 저장소 루트에서 관리자 계정으로 실행한다.
두 스크립트 모두 재실행해도 안전하며, 비밀번호는 psql 변수로만 넘긴다(파일에 쓰지 않는다).

```bash
set -a; . docker/.env; set +a   # VULN_APP_DB_PASSWORD, VALIDATION_DB_PASSWORD 로드

# 1) 취약 앱 role vuln_app 생성 + users/products 소유권 이전
docker exec -i postgres psql -U vulnuser -d vulndb -v apppw="$VULN_APP_DB_PASSWORD" < db/bootstrap/app_role.sql

# 2) 판정 결과 role/schema validation_rw·validation 생성 + vuln_app 차단
docker exec -i postgres psql -U vulnuser -d vulndb -v valpw="$VALIDATION_DB_PASSWORD" -v app_role=vuln_app \
  < db/bootstrap/validation_role.sql

# 3) target-web → suricata 순으로 재생성 (운영 규칙)
```

참고: 앱은 기동마다 `schema.sql` 로 `users`·`products` 를 DROP/CREATE 하므로, 1) 을 건너뛰면
`vuln_app` 이 테이블 소유자가 아니어서 기동에 실패한다.

## Git 제외 대상

`docker/.env`와 `docker/config/wazuh_indexer_ssl_certs/` 아래 인증서, key, pem 파일은 로컬 실행 산출물이므로 커밋하지 않는다.
