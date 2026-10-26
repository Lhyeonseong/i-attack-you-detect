-- validation schema v13 — BENIGN login 최종 상관판정
--
-- 목적:
--   NIDS/BACKEND_CORR 원시 판정은 validation.benign_result 에 그대로 보존하고,
--   BRUTE_FORCE 정상 트래픽에 대한 플랫폼 최종 판정을 별도 파생 뷰에서 계산한다.
--
-- 원칙:
--   1) NIDS 단독 ANALYTIC alert 는 원시 NIDS FP 로 보존한다.
--   2) BACKEND_CORR 시퀀스 alert(100231/100233)가 성립한 경우에만
--      플랫폼 최종 BF alert 로 승격한다.
--   3) NORMAL/TYPO 같은 실험 ground-truth 라벨은 판정 입력으로 사용하지 않는다.
--   4) 기존 benign_result / M14 / metric_scope / metric_snapshot 은 변경하지 않는다.

CREATE VIEW v_benign_final_result AS
SELECT
    q.run_id,
    q.seq,
    e.scenario,
    q.endpoint,
    q.status,

    COALESCE(n.alerted, FALSE) AS nids_alerted,
    COALESCE(n.alert_count, 0) AS nids_alert_count,
    COALESCE(n.linked_rule_ids, ARRAY[]::text[]) AS nids_rule_ids,

    COALESCE(b.alerted, FALSE) AS backend_corr_alerted,
    COALESCE(b.alert_count, 0) AS backend_corr_alert_count,
    COALESCE(b.linked_rule_ids, ARRAY[]::text[]) AS backend_corr_rule_ids,

    -- BF 최종 승격 조건:
    -- NIDS 단독 신호는 원시 센서 결과로만 보존하고,
    -- 실제 backend correlation sequence 가 성립한 경우에만 최종 alert.
    COALESCE(b.alerted, FALSE) AS final_alerted,

    CASE
        WHEN COALESCE(b.alerted, FALSE) THEN 'BACKEND_SEQUENCE'
        WHEN COALESCE(n.alerted, FALSE) THEN 'NIDS_ONLY'
        ELSE 'NO_ALERT'
    END AS decision_reason

FROM benign_request q
JOIN benign_endpoint e
  ON e.endpoint = q.endpoint
LEFT JOIN benign_result n
  ON n.run_id = q.run_id
 AND n.seq = q.seq
 AND n.control = 'NIDS'
LEFT JOIN benign_result b
  ON b.run_id = q.run_id
 AND b.seq = q.seq
 AND b.control = 'BACKEND_CORR'
WHERE e.scenario = 'BRUTE_FORCE';

COMMENT ON VIEW v_benign_final_result IS
    'V13: BENIGN BRUTE_FORCE 최종 상관판정. NIDS/BACKEND_CORR 원시 결과는 보존하고, '
    'BACKEND_CORR 시퀀스 성립 시에만 final_alerted=true. ground-truth scenario subtype(TYPO 등)는 사용하지 않는다.';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'validation_ro') THEN
    EXECUTE 'GRANT SELECT ON validation.v_benign_final_result TO validation_ro';
  END IF;
END $$;
