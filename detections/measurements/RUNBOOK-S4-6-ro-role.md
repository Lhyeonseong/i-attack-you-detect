# RUNBOOK-S4-6-ro-role — validation_ro 읽기 전용 role · V11 출처 · V12 권한

- 대상: ADR-S4-02 D2(validation_ro)·D11(run_provenance_note)·D3(권한 테스트 게이트).
- 실행 스크립트: `/tmp/s4-6-db.sh` (운영 DB 쓰기 포함 → [STOP-DB] 승인 후 현성 실행). 출력 `/tmp/s4-6-db.log`.
- 코드(커밋 대상): `db/bootstrap/validation_ro_role.sql`, `src/main/resources/db/validation/V11__run_provenance_note.sql`,
  `V12__validation_ro_grants.sql`, `db/provenance/2026-10-22_run_provenance_note_seed.sql`,
  테스트 `src/test/java/com/capstone/vuln/correlation/ValidationRoRoleTest.java`.

## 사전 조건
- 현성이 `docker/.env` 에 `VALIDATION_RO_PASSWORD=<openssl rand -base64 24>` 추가(값 화면 출력 금지).
- `.env.example` 에는 키 이름 placeholder 만(`VALIDATION_RO_PASSWORD=__GENERATE__`).

## TLS 파일 권한 (validation-api 기동 전제)
- 컨테이너는 `vapi`(uid·gid **10001**, Dockerfile `groupadd -g 10001 && useradd -u 10001 -g 10001`)로 실행, `docker/config/validation-api/tls` 를 `:ro` 마운트해 **그룹 읽기**로 접근.
- 파일 소유·모드(secrets.sh 적용): `tls/` 폴더 `현성:10001` **750**, `cert.pem`·`key.pem` `현성:10001` **640**(전체읽기 금지, 644 아님). 그룹 10001 변경은 `sudo chown $(id -u):10001`.

## 확정값 (근거)
- `statement_timeout = 40s` — Step1 공개 뷰 8개 EXPLAIN ANALYZE 최대 실행시간 v_metric_h2 **3960.586ms ×10 올림**
  (근거 `/tmp/s4-6-check.log` (D2); 다른 7개 뷰 ≤133ms).
- `CONNECTION LIMIT = 6` — API 커넥션 풀 최댓값 5 + 1(ADR D2). 소비자는 대시보드 1 + smoke/capture.
- SELECT 허용 18관계 = 공개 지표 뷰 12(rates·mttd·correlation·h2·coverage·attacker·m07a·m13·m14a·m14b·m14_rule·run_integrity)
  + API 뷰 2(`v_api_attempt`·`v_api_alert_link`) + 테이블 4(measurement_run·metric_snapshot·metric_snapshot_withdrawal·run_provenance_note).
  · `run_provenance_note` SELECT 는 ADR D2 허용목록에 명시 안 됐으나 D11(화면 ⑥ 출처)에 필요 → 포함(DRI 승인).
  · `v_api_alert_link` = detection_link 연결 경보(화면 ④). username·src_ip·alert_ref 미노출.
- EXECUTE 3함수 = wilson_ci·quantile_t8·newcombe_diff_ci(PUBLIC 회수분만 명시). compare_snapshots 는 부여 안 함(API 직접 join).

## 절차 = /tmp/s4-6-db.sh  (하드 게이트: 불일치 시 exit≠0)
0. 백업 `~/capstone-backups/2026-10-22_validation_pre-s4-6.sql`(pg_dump -n validation), 기준값 기록·검증
   (runs=19, snapshot_rows=442, s46_md5=`51b1999f95d4b18727f6257373f207de`).
0b. **출처 diff 게이트** → `/tmp/s4-6-provenance-diff.log`: 4개 run 의 git_commit 을 DB 에서 읽어
   `git diff --stat e3b5f52 <commit> -- docker/docker-compose.yml docker/.env.example build.gradle`(caldera 는 8b93151 기준)로
   이미지 digest 줄·Boot 버전 줄 변경이 0인지 확인. 변경 감지 run 이 있으면 **seed 전에 STOP**(append-only 보호). 계획 행 목록도 로그에 출력.
1. `validation_ro` 생성 — `db/bootstrap/validation_ro_role.sql`(관리자 role 로 실행, `-v ropw` `-v dbname`). 객체 권한은 V12.
2. V11·V12 적용 — 기존 진입점 `ValidationMigrateIT`. **호스트 포트는 docker/.env `POSTGRES_PORT`** 를 쓰고,
   `docker port postgres 5432/tcp` 매핑(= compose 호스트 포트, 보통 5433)과 **일치할 때만** 진행(불일치 시 별도 host postgres 접속 위험 → STOP).
   (`RUN_VALIDATION_MIGRATE=1 POSTGRES_PORT=<.env 값> POSTGRES_DB=vulndb VALIDATION_DB_PASSWORD=… ./gradlew test --tests '*ValidationMigrateIT'`).
   주의: (0)(0b)(3)(4) 는 `docker exec postgres psql` 로 컨테이너 내부 5432 를 쓰므로 호스트 포트와 무관.
3. 출처 seed — `db/provenance/2026-10-22_run_provenance_note_seed.sql`(validation_rw, ON CONFLICT DO NOTHING 재실행 안전).
4. 사후 확인(모두 PASS 여야 멈추지 않음, 불일치 시 exit 1):
   - 기준값 불변: runs=19, snapshot_rows=442, s46_md5 동일, flyway_max=12.
   - provenance_rows=**29**(b1c26be1=5, 적격 4 run×6[4종+caldera+stack_basis]).
   - 권한: SELECT=**18**관계, EXECUTE=3함수, 비-SELECT 권한=(none).
   - validation_ro 쓰기(INSERT)→permission denied, 기반 테이블 SELECT→denied, 허용 뷰 SELECT→OK.
   - V12 가드로 role 없이 migrate 되면 SELECT=0 → 사후 SELECT≠18 로 자동 STOP.

## role 없을 때(테스트 등) 처리 — 보고 대상
- `V12` 는 `DO $$ ... IF NOT EXISTS(pg_roles 'validation_ro') THEN RETURN` 가드로 **role 없으면 GRANT 건너뜀**.
  기존 V 파일은 validation_rw 존재를 전제하지만 validation_ro 는 S4-6 bootstrap 에서만 생기므로 가드를 둔다.
  운영 db.sh 는 `(1) role 생성 → (2) migrate` 순서라 항상 적용되고, `ValidationRoRoleTest` 는 전용 컨테이너에서
  role 생성 후 migrate 해 허용목록을 검증한다. 공유 테스트 컨테이너(ValidationDbFixture)에서는 GRANT 가 건너뛰어져 기존 테스트에 영향 없음.

## D11 출처 seed — 원천(파일:줄) · diff 게이트 기반(결정 B)
- b1c26be1(기준 run): 전용 줄 `2026-10-21_s6-baseline.log:2`(suricata·wazuh·pg·boot) + caldera `2026-10-20_4-caldera-pin.log:2`. (5행)
- 805f3b8e·2ad849e0·3818e21a·7fc9767f: e3b5f52 대비 compose·.env.example·build.gradle 의 digest/Boot 줄 변경 0,
  caldera 는 8b93151 대비 변경 0 임을 `/tmp/s4-6-provenance-diff.log` 로 확인한 **적격 run**.
  · 공용 줄 `2026-10-21_reboot-verify.log:2`(suricata·wazuh·pg·boot) + caldera `…4-caldera-pin.log:2`
  · item=`stack_basis` 1행: value=`digest-pinned images & Boot unchanged since e3b5f52 (caldera since 8b93151)`,
    source=`detections/measurements/evidence/2026-10-22_s4-6-provenance-diff.log`(diff 증거). (각 6행)
- 변경 감지 run 은 넣지 않음(화면 "기록 없음"). 현재 4개 모두 변경 0 확인(2026-10-22). 합계 29행.
