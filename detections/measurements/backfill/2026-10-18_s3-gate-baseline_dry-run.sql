-- S4-1 백필 dry-run — UPDATE 없이 귀속·역할 예정 건수만 출력 (읽기 전용 트랜잭션)
-- 전제: V2 적용 완료. 대상·조건은 2026-10-18_s3-gate-baseline.sql 과 동일.
--
-- 실행: docker exec -i postgres psql -U validation_rw -d <POSTGRES_DB> -v ON_ERROR_STOP=1 \
--         < detections/measurements/backfill/2026-10-18_s3-gate-baseline_dry-run.sql
-- 기대: 귀속 160 (창 밖 run_id NULL 0), ATTACK 140·CONTROL 20, 대조군은 전부 SSRF, R10 VALID, 기존 run 0

\set ON_ERROR_STOP on

-- 대조군 unit_key 20건 (SSRF CTL="http://example.com/" 요청, Step 0 앱 로그 대조) — 본 스크립트 3단계와 동일
\set controls '(''unit:01210ee2-cf69-45d8-af25-cd377970d22e'', ''unit:06d6f79a-a0bc-46f2-9400-9e0944cd5cf1'', ''unit:0fb31ee0-9cae-441b-8977-39639845831d'', ''unit:19a8c63e-16ce-43cb-9dd3-ec7104dd0ffc'', ''unit:31907ed5-9c28-435a-a86e-5ba2fbd42477'', ''unit:3b05c658-247e-4ee3-87cf-29d18c902ee6'', ''unit:59fe501d-a491-462d-ad49-79214c569b5d'', ''unit:65b868c3-8c87-4fc0-8a3b-b0b43cae62f5'', ''unit:8ab1c582-d71e-4242-ae23-761393c1166d'', ''unit:8b7c0781-84ee-44c2-bcff-7530d3d83fd9'', ''unit:a532da22-5cc3-46f2-b5eb-fd72e77310a5'', ''unit:a6b2df8b-79aa-4a02-853a-f4ba7e590ad7'', ''unit:b9e60b73-4536-4c0b-ac70-f4944876db54'', ''unit:be777869-9355-4aad-af19-d7f17fd4c9cd'', ''unit:ce004f17-6d73-4e74-9aed-c61349a8d737'', ''unit:e67269bd-3c96-4414-b89f-f1c9921ee47d'', ''unit:f2393657-40f5-4fd7-974c-a31107ccf456'', ''unit:f36c9b22-f167-4b61-8dc8-a55800e8c04c'', ''unit:f41a546e-250e-48f7-a416-4c23bbcad9ea'', ''unit:fe3246ea-297c-4547-bb7e-33b537e2ac94'')'
\set target 'SELECT v.*, CASE WHEN v.unit_key IN ' :controls ' THEN ''CONTROL'' ELSE ''ATTACK'' END AS planned_role FROM validation.verdict_result v WHERE v.run_id IS NULL AND v.decided_at >= ''2026-10-16 17:04:00Z'' AND v.decided_at < ''2026-10-16 18:08:00Z'''

BEGIN READ ONLY;

-- 1. 귀속 예정 건수 / 창 밖 run_id NULL (0 이어야 백필 후 잔여 0)
WITH t AS (:target)
SELECT count(*)                                            AS to_attribute,
       count(*) FILTER (WHERE planned_role = 'ATTACK')     AS planned_attack,
       count(*) FILTER (WHERE planned_role = 'CONTROL')    AS planned_control,
       min(decided_at)                                     AS started_at,
       max(decided_at)                                     AS ended_at,
       (SELECT count(*) FROM validation.verdict_result WHERE run_id IS NULL) - count(*) AS null_outside_window
  FROM t;

-- 2. 시나리오 × 예정 role × verdict
WITH t AS (:target)
SELECT scenario, planned_role, verdict, count(*) FROM t GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;

-- 3. R10 예측 (expected 140·20)
WITH t AS (:target)
SELECT 140 AS expected_attempts, count(*) FILTER (WHERE planned_role = 'ATTACK') AS attack,
       20 AS expected_controls, count(*) FILTER (WHERE planned_role = 'CONTROL') AS control,
       CASE WHEN count(*) FILTER (WHERE planned_role = 'ATTACK') = 140
             AND count(*) FILTER (WHERE planned_role = 'CONTROL') = 20 THEN 'VALID' ELSE 'INVALID' END AS r10
  FROM t;

-- 4. 중복 백필 여부 (0 이어야 함)
SELECT count(*) AS existing_runs FROM validation.measurement_run
 WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727' OR label = 'S3-GATE-dc66322';

ROLLBACK;
