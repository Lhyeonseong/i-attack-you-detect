# RUNBOOK S4-3 — V5 metric_snapshot 적용 + 스냅샷 실행 (초안, 실행: 이현성)

- 목적: ADR-S4-01 v1.6 R13 — VALID run 의 S4-2 지표 뷰 결과를 측정 시점 값으로 고정(기록 층). 라이브 뷰(V4)는 그대로 둔다
- 성격: **운영 validation DB 쓰기** — (1) V5 마이그레이션, (3) 스냅샷 INSERT. 스냅샷은 지울 수 없다(잘못되면 철회만)
- 위치: 저장소 루트(`docker/.env` 가 있는 develop-v2 체크아웃, V5 커밋 이후)
- 계정: `validation_rw`(validation 스키마 소유자, superuser 아님). 비밀값은 `$(grep … docker/.env)` 로만 넘기고 출력하지 않는다
- 증거: 전 과정을 `tee -a detections/measurements/evidence/<날짜>_s4-3-snapshot.log` 로 남긴다
- 대상 run(DRI 결정): `S4-STACK-6-BASELINE`(새 baseline) 필수. `S3-GATE-dc66322`(백필 run — git_dirty NULL, rules_digest `unverified`)는 선택
- 정의 버전: `definition_version` = 원 지표 뷰들의 값(현재 `ADR-S4-01 v1.4`)을 함수가 자동으로 쓴다(R13 e, 뷰마다 다르면 거부).
  `snapshot_rule_version` = `ADR-S4-01 v1.6`(상수). 지표 정의가 바뀌면(R7) 새 definition_version 행으로 추가된다(기존 행 수정 금지)
- 주의: CampaignRunnerIT(스모크·본측정)도 시작할 때 `ValidationSchemaMigrator.migrate` 를 부른다(ValidationPersistenceConfig.java:39).
  (1) 전에 측정을 돌리면 V5 가 측정 시작 때 적용된다 — (1) 을 먼저 끝내고, 이 RUNBOOK 이 끝날 때까지 측정을 돌리지 않는다
- 어느 단계든 "멈출 것"이 나오면 다음 단계로 가지 말고 출력 그대로 공유

---

## (0) 사전 점검 (읽기 전용) + 백업

```bash
git log --oneline -1 && git status --porcelain | wc -l
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL'
BEGIN READ ONLY;
SELECT label, run_id, kind, status, r10_status, r10_reason FROM validation.v_run_integrity
 WHERE label IN ('S4-STACK-6-BASELINE', 'S3-GATE-dc66322') ORDER BY label;
SELECT installed_rank, version, checksum, success FROM validation.flyway_schema_history ORDER BY installed_rank;
SELECT to_regclass('validation.metric_snapshot') AS snapshot_table;
ROLLBACK;
SQL
B=~/capstone-backups/$(date +%F)_validation_pre-v5.sql
test -e "$B" && echo "EXISTS — 덮어쓰지 않음" || docker exec postgres sh -c 'pg_dump -U validation_rw -d "$POSTGRES_DB" -n validation --no-owner' > "$B"
ls -l "$B" && sha256sum "$B"
```

정상 출력 예시:
```
<HEAD 해시> …                     ← V5 커밋 이후
0
 S3-GATE-dc66322     | bd2de561-… | ATTACK | CLOSED | VALID |
 S4-STACK-6-BASELINE | b1c26be1-… | ATTACK | CLOSED | VALID |
 1 | 1 | -302875525  | t   …   4 | 4 | -254580708 | t     ← V1~V4 만
 snapshot_table = (빈칸)                                 ← V5 미적용
-rw-… <크기> …_validation_pre-v5.sql
```

멈출 것: 대상 run 이 VALID 아님, `flyway_schema_history` 에 5 가 이미 있음(누가 먼저 적용 — 경위 확인), 백업 파일 크기 0.

## (1) V5 적용 — migrate 전용 진입점 (측정·Caldera 호출 없음)

```bash
RUN_VALIDATION_MIGRATE=1 \
POSTGRES_DB="$(grep -m1 '^POSTGRES_DB=' docker/.env | cut -d= -f2-)" \
VALIDATION_DB_PASSWORD="$(grep -m1 '^VALIDATION_DB_PASSWORD=' docker/.env | cut -d= -f2-)" \
./gradlew cleanTest test --tests 'com.capstone.vuln.correlation.ValidationMigrateIT' -i 2>&1 \
  | grep -E 'MIGRATE>>|ValidationMigrateIT|FAILED|BUILD'
```

정상 출력 예시:
```
    MIGRATE>> before=[1, 2, 3, 4] after=[1, 2, 3, 4, 5]
    MIGRATE>>   rank=5 v=5 metric snapshot by=validation_rw on=<지금> success=true
BUILD SUCCESSFUL in ...
```

멈출 것: `migrate() SKIPPED`(env 미주입), `FAILED`, `Validate failed`·`checksum mismatch`, `after` 에 `5` 없음.

## (2) dry-run (대상 run 마다, 저장 안 함)

```bash
RUN=b1c26be1-add2-4d45-8207-0998b0f743b1   # S4-STACK-6-BASELINE (S3-GATE 는 bd2de561-a7dc-429f-8d39-fc2d70950727)
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL'
BEGIN;
SELECT validation.take_metric_snapshot(:'run') AS inserted;
SELECT definition_version, snapshot_rule_version, source_view, count(*) FROM validation.metric_snapshot WHERE run_id = :'run' GROUP BY 1, 2, 3 ORDER BY 3;
-- I1: M02 + M03 = 1 (분모 > 0) — 위반 행 수
SELECT count(*) AS i1_violations FROM validation.metric_snapshot a JOIN validation.metric_snapshot b
  ON b.run_id = a.run_id AND b.definition_version = a.definition_version AND b.metric_id = 'M03'
 AND b.scope_kind = a.scope_kind AND b.scope_key = a.scope_key
 WHERE a.run_id = :'run' AND a.metric_id = 'M02' AND a.denominator > 0
   AND (a.numerator + b.numerator <> a.denominator OR a.denominator <> b.denominator);
-- I6: Σ 시나리오 n = ALL n = Σ 기법 n (M08)
SELECT scope_kind, sum(denominator) FROM validation.metric_snapshot
 WHERE run_id = :'run' AND metric_id = 'M08' GROUP BY 1 ORDER BY 1;
-- 표기 확인 (R13 f): M02 ALL
SELECT numerator || '/' || denominator AS x_n, point_estimate, ci_lower, ci_upper, status
  FROM validation.metric_snapshot WHERE run_id = :'run' AND metric_id = 'M02' AND scope_kind = 'ALL';
ROLLBACK;
SQL
```

정상 출력 예시(S4-STACK-6-BASELINE — 지표 뷰 행 rates 52·mttd 7·correlation 20·h2 1·coverage 4·attacker 4, 2026-10-21 읽기):
```
 inserted = 89                        ← 52 + 7 + 20 + 2(H2 1행 = 관측 2개) + 4 + 4
 ADR-S4-01 v1.4 | ADR-S4-01 v1.6 | v_metric_attacker 4 / v_metric_correlation 20 / v_metric_coverage 4 / v_metric_h2 2 / v_metric_mttd 7 / v_metric_rates 52
 i1_violations = 0
 ALL 140 / SCENARIO 140 / TECHNIQUE 140
 x_n 120/140 | 0.857… | <하한> | <상한> | OK
ROLLBACK
```

멈출 것: 예외(R10·definition_version 불일치·중복 메시지), `inserted` 가 위 합과 다름, `i1_violations` ≠ 0, I6 세 합이 다름,
`definition_version` 이 `ADR-S4-01 v1.4` 가 아님.

## (3) 실제 실행 (대상 run 마다 COMMIT)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v run='"$RUN" <<'SQL'
BEGIN;
SELECT validation.take_metric_snapshot(:'run') AS inserted;
COMMIT;
SQL
```

멈출 것: `inserted` 가 (2) 와 다름, 예외. 두 번 실행하면 `스냅샷이 이미 있다` 예외가 정상(덮어쓰기 금지).

## (4) 사후 확인 (불변 확인은 트랜잭션 안에서 시도 후 ROLLBACK)

```bash
docker exec -i postgres sh -c 'psql -U validation_rw -d "$POSTGRES_DB" -v run='"$RUN" <<'SQL'
SELECT run_label, definition_version, schema_version, left(git_commit, 12), git_dirty, count(*), min(snapshot_at), max(snapshot_at)
  FROM validation.metric_snapshot WHERE run_id = :'run' GROUP BY 1, 2, 3, 4, 5;
BEGIN;
UPDATE validation.metric_snapshot SET numerator = 0 WHERE run_id = :'run';
ROLLBACK;
BEGIN;
DELETE FROM validation.metric_snapshot WHERE run_id = :'run';
ROLLBACK;
SQL
```

정상 출력 예시:
```
 S4-STACK-6-BASELINE | ADR-S4-01 v1.4 | 5 | e3b5f5285152 | f | 89 | <시각> | <같은 시각>
ERROR:  permission denied for table metric_snapshot      ← UPDATE
ERROR:  permission denied for table metric_snapshot      ← DELETE
```

멈출 것: 행 수 ≠ (3), UPDATE·DELETE 가 성공(`UPDATE 89` 등).

## (5) 마무리

- 증거 로그를 explicit pathspec 으로 커밋(`git commit -- detections/measurements/evidence/<날짜>_s4-3-snapshot.log`)
- 잘못 찍은 스냅샷은 지우지 않는다: `SELECT validation.withdraw_metric_snapshot('<run_id>', 'ADR-S4-01 v1.4', '<사유>');`
- 소유자(validation_rw)는 트리거를 끄거나 권한을 되돌릴 수 있다 — 불변은 일반 DML 기준(known-gaps Gap #8)
