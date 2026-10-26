-- S4-1 백필: S3 20회 게이트 측정(verdict_result 160행)을 measurement_run 1개에 귀속 + 대조군 역할 표시
-- ADR-S4-01 v1.1 R4·R6·R10. 근거: S4-1 Step 0 (2026-10-18, 읽기 전용 조회)
--
-- 전제: V2__measurement_run.sql 적용 완료 (measurement_run, verdict_result.run_id uuid, attempt_role)
-- 먼저 같은 폴더의 2026-10-18_s3-gate-baseline_dry-run.sql 로 귀속 예정 건수를 확인할 것.
--
-- 실행(사람이 직접, 운영 DB 쓰기):
--   docker cp detections/measurements/backfill/2026-10-18_s3-gate-baseline.sql postgres:/tmp/backfill.sql
--   docker exec -it postgres psql -U validation_rw -d <POSTGRES_DB>
--   =# \i /tmp/backfill.sql      -- 검증 SELECT 확인 후
--   =# COMMIT;                    -- (문제 있으면 ROLLBACK;)
--   stdin 으로 흘려 넣으면 마지막 COMMIT 이 없어 세션 종료 시 자동 롤백된다(리허설 용도).
--
-- 귀속 근거 (Step 0):
--   - CampaignRunnerIT(truncate=true) 1회 = op 20회. save 1회 = 트랜잭션 1개라 decided_at(트랜잭션 시작 시각)이
--     op 1회를 식별: distinct 20개 × 8행(SQLi 1·PT 3·SSRF 3·BF 1), 17:04:01.091971Z ~ 18:07:23.246309Z
--   - correlation.op_id 는 160행 모두 NULL(OperationResolver 미호출) → op_id 로는 묶을 수 없음
--   - 측정 코드 = 17a0b04 (측정 02:00~03:07 KST 당시 HEAD). dc66322 는 리포트·노트만 추가(코드 동일)
--   - 대조군 20건 = SSRF ability(a7f3c1d9…) 요청 중 앱 로그 http_request.args = 'url=http://example.com/' 인 rid
--     (정답지 쪽 요청 대상으로 판별, 탐지 결과 미참조). 160 unit 의 rid 전부 앱 로그에서 확인
--   - expected_attempts 140 = (SQLi 1 + PT 3 + SSRF 2 + BF 1) × op 20, expected_controls 20 = SSRF 대조 1 × op 20
--     (게이트 리포트 gate-report-2026-10-16T18-07-23-315Z: SQLi 20·PT 60·SSRF 60·BF 20 = 160)
-- DELETE 없음. 게이트·결론은 재분류로 바꾸지 않는다(ADR M09 비고) — 이 스크립트는 귀속·역할 표시만 한다.

\set ON_ERROR_STOP on

BEGIN;

-- 0. 사전 확인 — 하나라도 어긋나면 중단(트랜잭션 롤백)
DO $$
DECLARE
    n_window   integer;
    n_null     integer;
    t_min      timestamptz;
    t_max      timestamptz;
    n_ctl      integer;
BEGIN
    SELECT count(*), count(*) FILTER (WHERE run_id IS NULL), min(decided_at), max(decided_at)
      INTO n_window, n_null, t_min, t_max
      FROM validation.verdict_result
     WHERE decided_at >= '2026-10-16 17:04:00Z' AND decided_at < '2026-10-16 18:08:00Z';
    IF n_window <> 160 OR n_null <> 160 THEN
        RAISE EXCEPTION '대상 창 행 수 불일치: window=% run_id_null=% (기대 160/160)', n_window, n_null;
    END IF;
    IF t_min <> '2026-10-16 17:04:01.091971Z' OR t_max <> '2026-10-16 18:07:23.246309Z' THEN
        RAISE EXCEPTION 'decided_at 범위 불일치: % ~ %', t_min, t_max;
    END IF;
    IF EXISTS (SELECT 1 FROM validation.measurement_run
                WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727' OR label = 'S3-GATE-dc66322') THEN
        RAISE EXCEPTION '이미 백필됨 (run_id 또는 label 존재)';
    END IF;
    SELECT count(*) INTO n_ctl FROM validation.verdict_result
     WHERE scenario = 'SSRF' AND unit_key IN (
        'unit:01210ee2-cf69-45d8-af25-cd377970d22e', 'unit:06d6f79a-a0bc-46f2-9400-9e0944cd5cf1',
        'unit:0fb31ee0-9cae-441b-8977-39639845831d', 'unit:19a8c63e-16ce-43cb-9dd3-ec7104dd0ffc',
        'unit:31907ed5-9c28-435a-a86e-5ba2fbd42477', 'unit:3b05c658-247e-4ee3-87cf-29d18c902ee6',
        'unit:59fe501d-a491-462d-ad49-79214c569b5d', 'unit:65b868c3-8c87-4fc0-8a3b-b0b43cae62f5',
        'unit:8ab1c582-d71e-4242-ae23-761393c1166d', 'unit:8b7c0781-84ee-44c2-bcff-7530d3d83fd9',
        'unit:a532da22-5cc3-46f2-b5eb-fd72e77310a5', 'unit:a6b2df8b-79aa-4a02-853a-f4ba7e590ad7',
        'unit:b9e60b73-4536-4c0b-ac70-f4944876db54', 'unit:be777869-9355-4aad-af19-d7f17fd4c9cd',
        'unit:ce004f17-6d73-4e74-9aed-c61349a8d737', 'unit:e67269bd-3c96-4414-b89f-f1c9921ee47d',
        'unit:f2393657-40f5-4fd7-974c-a31107ccf456', 'unit:f36c9b22-f167-4b61-8dc8-a55800e8c04c',
        'unit:f41a546e-250e-48f7-a416-4c23bbcad9ea', 'unit:fe3246ea-297c-4547-bb7e-33b537e2ac94')
       AND decided_at >= '2026-10-16 17:04:00Z' AND decided_at < '2026-10-16 18:08:00Z';
    IF n_ctl <> 20 THEN
        RAISE EXCEPTION '대조군 unit_key 20건 중 % 건만 창 안 SSRF 로 존재', n_ctl;
    END IF;
END $$;

-- 1. run 1건 (baseline, CLOSED)
INSERT INTO validation.measurement_run (run_id, label, kind, status, started_at, ended_at, git_commit, git_dirty,
    rules_digest, expected_attempts, expected_controls, notes)
VALUES ('bd2de561-a7dc-429f-8d39-fc2d70950727', 'S3-GATE-dc66322', 'ATTACK', 'CLOSED',
    '2026-10-16 17:04:01.091971Z', '2026-10-16 18:07:23.246309Z',
    '17a0b04', NULL,
    '{"status": "unverified",
      "reason": "single-file bind-mount, runtime rules unprovable",
      "observed_after": {
        "observed_at": "2026-10-18",
        "verdict": "inconsistent",
        "why": "containers restarted after measurement (StartedAt 2026-10-18T07:59Z > 2026-10-16T17:04Z); file hashes match 17a0b04 but runtime at measurement time is not observable",
        "wazuh_manager": {"started_at": "2026-10-18T07:59:35Z", "vuln_rules_xml": "47715556fd0fd7c9c8449d8308c454074884a07a996996ce9fe0dd07d1e239cb", "matches_17a0b04": true},
        "suricata": {"started_at": "2026-10-18T07:59:40Z", "local_rules": "007b188d4e80f10582668659f6db9f02b5047af1fa72cbefa295b42601a947a4", "matches_17a0b04": true},
        "caldera": {"started_at": "2026-10-18T07:59:35Z", "attack_validation_web_yml": "cba127e95e913f68b9ee650e9bfbec80d3b517dd445e5063d8211ceab6b8d3f2", "abilities_4_match_17a0b04": true}
      }}'::jsonb,
    140, 20,
    'backfilled; code 17a0b04, report dc66322; dirty unknown');

-- 2. verdict 160행 run 귀속 (UPDATE — CLOSED run 트리거는 INSERT 만 막는다)
UPDATE validation.verdict_result
   SET run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727'
 WHERE run_id IS NULL
   AND decided_at >= '2026-10-16 17:04:00Z' AND decided_at < '2026-10-16 18:08:00Z';

-- 3. 대조군 20건 (SSRF CTL="http://example.com/" 요청, Step 0 앱 로그 대조)
UPDATE validation.verdict_result
   SET attempt_role = 'CONTROL'
 WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727'
   AND unit_key IN (
    'unit:01210ee2-cf69-45d8-af25-cd377970d22e', 'unit:06d6f79a-a0bc-46f2-9400-9e0944cd5cf1',
    'unit:0fb31ee0-9cae-441b-8977-39639845831d', 'unit:19a8c63e-16ce-43cb-9dd3-ec7104dd0ffc',
    'unit:31907ed5-9c28-435a-a86e-5ba2fbd42477', 'unit:3b05c658-247e-4ee3-87cf-29d18c902ee6',
    'unit:59fe501d-a491-462d-ad49-79214c569b5d', 'unit:65b868c3-8c87-4fc0-8a3b-b0b43cae62f5',
    'unit:8ab1c582-d71e-4242-ae23-761393c1166d', 'unit:8b7c0781-84ee-44c2-bcff-7530d3d83fd9',
    'unit:a532da22-5cc3-46f2-b5eb-fd72e77310a5', 'unit:a6b2df8b-79aa-4a02-853a-f4ba7e590ad7',
    'unit:b9e60b73-4536-4c0b-ac70-f4944876db54', 'unit:be777869-9355-4aad-af19-d7f17fd4c9cd',
    'unit:ce004f17-6d73-4e74-9aed-c61349a8d737', 'unit:e67269bd-3c96-4414-b89f-f1c9921ee47d',
    'unit:f2393657-40f5-4fd7-974c-a31107ccf456', 'unit:f36c9b22-f167-4b61-8dc8-a55800e8c04c',
    'unit:f41a546e-250e-48f7-a416-4c23bbcad9ea', 'unit:fe3246ea-297c-4547-bb7e-33b537e2ac94');

-- 4. 사후 확인 — 어긋나면 중단
DO $$
DECLARE
    n_run   integer;
    n_att   integer;
    n_ctl   integer;
    n_null  integer;
BEGIN
    SELECT count(*), count(*) FILTER (WHERE attempt_role = 'ATTACK'), count(*) FILTER (WHERE attempt_role = 'CONTROL')
      INTO n_run, n_att, n_ctl
      FROM validation.verdict_result WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727';
    SELECT count(*) INTO n_null FROM validation.verdict_result WHERE run_id IS NULL;
    IF n_run <> 160 OR n_att <> 140 OR n_ctl <> 20 OR n_null <> 0 THEN
        RAISE EXCEPTION '사후 확인 실패: run=% ATTACK=% CONTROL=% run_id_null=% (기대 160/140/20/0)',
            n_run, n_att, n_ctl, n_null;
    END IF;
END $$;

-- 5. 검증 SELECT
-- 5-1 귀속·역할 건수 / run_id NULL 잔여
SELECT count(*)                                          AS attributed,
       count(*) FILTER (WHERE attempt_role = 'ATTACK')   AS attack,
       count(*) FILTER (WHERE attempt_role = 'CONTROL')  AS control,
       (SELECT count(*) FROM validation.verdict_result WHERE run_id IS NULL) AS run_id_null_remaining
  FROM validation.verdict_result WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727';

-- 5-2 시나리오 × role × verdict
SELECT scenario, attempt_role, verdict, count(*)
  FROM validation.verdict_result WHERE run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727'
 GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;

-- 5-3 R10 (expected vs 실제, ATTACK·CONTROL 둘 다 일치해야 VALID)
SELECT r.label, r.expected_attempts, a.attack, r.expected_controls, a.control,
       CASE WHEN r.expected_attempts = a.attack AND r.expected_controls = a.control THEN 'VALID' ELSE 'INVALID' END AS r10
  FROM validation.measurement_run r
  CROSS JOIN LATERAL (
        SELECT count(*) FILTER (WHERE attempt_role = 'ATTACK') AS attack,
               count(*) FILTER (WHERE attempt_role = 'CONTROL') AS control
          FROM validation.verdict_result v WHERE v.run_id = r.run_id) a
 WHERE r.run_id = 'bd2de561-a7dc-429f-8d39-fc2d70950727';

-- COMMIT;
