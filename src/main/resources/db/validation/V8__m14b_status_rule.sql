-- validation schema v8 (S4-5) — ADR-S4-01 v1.9: M14b 비적용 통제 상태를 M13·M14a 와 같은 규칙으로
-- V7 의 M14b 는 "그 run 에 통제 적용 요청 없음 → NOT_APPLICABLE" 로 따로 판정해, BACKEND_CORR × 웹 엔드포인트가
-- M14a·M13 은 NO_RULE(R18 b·R16), M14b 는 NOT_APPLICABLE 로 어긋났다(2026-10-22 S4-5-BENIGN-WEB-R2 (4) 확인, 스냅샷 전).
-- 고침: 통제의 M14a 칸이 모두 비적용(NO_RULE·NOT_APPLICABLE)이면 M14b 상태 = 그 상태(NO_RULE 우선). 값 계산은 그대로.
-- M14 뷰 정의가 바뀌었으므로 두 M14 뷰의 definition_version 을 'ADR-S4-01 v1.9' 로 올린다(R7 — v1.8 스냅샷 0행일 때 적용).
-- v_metric_m14a 는 본문 그대로·상수만, ATTACK 쪽 뷰·함수·테이블은 손대지 않는다.

CREATE OR REPLACE VIEW v_metric_m14a AS
WITH cell AS (
    SELECT r.run_id, c.unit AS control, e.endpoint, e.scenario
    FROM v_benign_run r
    CROSS JOIN metric_scope c
    JOIN benign_endpoint e ON EXISTS (SELECT 1 FROM benign_request q WHERE q.run_id = r.run_id AND q.endpoint = e.endpoint)
    WHERE c.kind = 'CONTROL'
), agg AS (
    SELECT cell.*,
           (SELECT count(*) FROM benign_request q
            WHERE q.run_id = cell.run_id AND q.endpoint = cell.endpoint AND q.matched_rid IS NOT NULL) AS n,
           (SELECT count(*) FROM benign_result b JOIN benign_request q ON q.run_id = b.run_id AND q.seq = b.seq
            WHERE b.run_id = cell.run_id AND q.endpoint = cell.endpoint AND b.control = cell.control AND b.alerted) AS x,
           (SELECT count(*) FROM benign_result b JOIN benign_request q ON q.run_id = b.run_id AND q.seq = b.seq
            WHERE b.run_id = cell.run_id AND q.endpoint = cell.endpoint AND b.control = cell.control) AS judged
    FROM cell
), judged AS (
    SELECT a.*,
           CASE
               WHEN a.control = 'APP_RULE' AND a.scenario = 'BRUTE_FORCE' THEN 'NOT_APPLICABLE'
               WHEN a.control = 'BACKEND_CORR' AND a.scenario <> 'BRUTE_FORCE' THEN 'NO_RULE'
               WHEN a.control = 'NIDS' AND NOT EXISTS (SELECT 1 FROM nids_sid_class k
                                                       WHERE k.class = 'ANALYTIC' AND k.scenario = a.scenario)
                   THEN 'NO_RULE'
               WHEN a.judged <> a.n THEN 'RESULT_MISMATCH'
               WHEN a.n = 0 THEN 'NO_DATA'
               ELSE 'OK'
           END AS status
    FROM agg a
)
SELECT j.run_id, 'ADR-S4-01 v1.9'::text AS definition_version, 'M14a_' || j.control AS metric_id, j.control,
       'SCENARIO'::text AS split_kind, j.scenario AS split_unit, j.endpoint,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END AS x, j.n, w.p, w.lo, w.hi, j.status
FROM judged j
LEFT JOIN LATERAL wilson_ci(CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.x END, j.n) w ON true;

CREATE OR REPLACE VIEW v_metric_m14b AS
WITH pair AS (
    SELECT r.run_id,
           (SELECT a.run_id
            FROM v_run_integrity a
            JOIN measurement_run ma ON ma.run_id = a.run_id
            WHERE a.kind = 'ATTACK' AND a.r10_status = 'VALID' AND ma.rules_digest = mb.rules_digest
              AND EXISTS (SELECT 1 FROM metric_snapshot s WHERE s.run_id = a.run_id)
            ORDER BY ma.started_at DESC, a.run_id
            LIMIT 1) AS paired_run_id
    FROM v_benign_run r
    JOIN measurement_run mb ON mb.run_id = r.run_id
), cell AS (
    SELECT p.run_id, p.paired_run_id, c.unit AS control,
           (SELECT count(*) FROM benign_result b WHERE b.run_id = p.run_id AND b.control = c.unit) AS judged,
           (SELECT coalesce(sum(b.alert_count), 0) FROM benign_result b
            WHERE b.run_id = p.run_id AND b.control = c.unit) AS fp_alerts,
           (SELECT count(*)
            FROM verdict_result v
            JOIN verdict_member m ON m.verdict_id = v.id
            JOIN detection_link l ON l.correlation_id = m.correlation_id
            WHERE v.run_id = p.paired_run_id AND v.attempt_role = 'ATTACK' AND l.confidence >= 0.7
              AND l.technique IS NOT DISTINCT FROM v.technique_id
              AND CASE c.unit
                      WHEN 'APP_RULE' THEN l.control = 'APP_RULE'
                      WHEN 'NIDS' THEN l.control = 'NIDS'
                          AND l.rule_id IN (SELECT k.sid::text FROM nids_sid_class k WHERE k.class = 'ANALYTIC')
                      ELSE l.control = 'APP_RULE' AND v.unit_type IN ('BF_SEQUENCE', 'SPRAY_CAMPAIGN')
                          AND v.detection_status = 'DETECTED'
                  END) AS tp_alerts,
           EXISTS (SELECT 1 FROM nids_window_stat w WHERE w.run_id = p.paired_run_id) AS pair_nids_collected,
           -- v1.9: 통제의 M14a 칸이 모두 비적용이면 그 상태를 그대로(M13·M14a 와 같은 규칙, NO_RULE 우선)
           (SELECT CASE
                       WHEN bool_or(a.status NOT IN ('NO_RULE', 'NOT_APPLICABLE')) THEN NULL
                       WHEN bool_or(a.status = 'NO_RULE') THEN 'NO_RULE'
                       ELSE 'NOT_APPLICABLE'
                   END
            FROM v_metric_m14a a WHERE a.run_id = p.run_id AND a.control = c.unit) AS inapplicable
    FROM pair p
    CROSS JOIN metric_scope c
    WHERE c.kind = 'CONTROL'
), judged AS (
    SELECT c.*, c.fp_alerts + c.tp_alerts AS n,
           CASE
               WHEN c.inapplicable IS NOT NULL THEN c.inapplicable
               WHEN c.judged = 0 THEN 'NOT_APPLICABLE'
               WHEN c.paired_run_id IS NULL THEN 'NO_PAIR'
               WHEN c.control = 'NIDS' AND NOT c.pair_nids_collected THEN 'NOT_COLLECTED'
               WHEN c.fp_alerts + c.tp_alerts = 0 THEN 'NO_DATA'
               ELSE 'OK'
           END AS status
    FROM cell c
)
SELECT j.run_id, 'ADR-S4-01 v1.9'::text AS definition_version, 'M14b_' || j.control AS metric_id, j.control,
       'ALL'::text AS split_kind, 'ALL'::text AS split_unit, j.paired_run_id,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.fp_alerts END AS x,
       CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.n END AS n,
       w.p, w.lo, w.hi, j.status
FROM judged j
LEFT JOIN LATERAL wilson_ci(CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.fp_alerts END,
                            CASE WHEN j.status IN ('OK', 'NO_DATA') THEN j.n END) w ON true;

DO $$
DECLARE
    v text;
BEGIN
    FOREACH v IN ARRAY ARRAY['v_metric_m14a', 'v_metric_m14b'] LOOP
        EXECUTE format('COMMENT ON VIEW validation.%I IS %L', v,
            replace(obj_description(('validation.' || v)::regclass, 'pg_class'), 'ADR-S4-01 v1.8', 'ADR-S4-01 v1.9')
            || ' — v1.9(V8): 비적용 통제 상태는 M14a 칸 상태를 따른다(M13·M14a·M14b 같은 규칙)');
    END LOOP;
END;
$$;
