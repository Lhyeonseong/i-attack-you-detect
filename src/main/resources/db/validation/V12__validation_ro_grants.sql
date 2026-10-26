-- V12 — validation_ro 읽기 전용 권한 (ADR-S4-02 D2). 이 목록이 전부다(초과·누락 테스트 게이트, D3).
--
-- role 가드: 기존 V 파일은 validation_rw 존재를 전제하지만, validation_ro 는 S4-6 bootstrap
--   (db/bootstrap/validation_ro_role.sql)에서만 생성된다. 테스트 등 role 이 없는 환경에서는
--   GRANT 를 건너뛴다(운영 db.sh 는 role 생성 → migrate 순서라 항상 적용됨). [STOP-DB 보고 대상]
--
-- DEFAULT PRIVILEGES 금지(쓰면 기반 테이블까지 열림). 기반 테이블·중간 뷰에는 권한 주지 않음
--   (공개 뷰는 security_invoker=false 라 소유자 권한으로 기반 테이블을 읽음).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'validation_ro') THEN
    RAISE NOTICE 'validation_ro 없음 — V12 GRANT 건너뜀(테스트/부분 환경)';
    RETURN;
  END IF;

  EXECUTE 'GRANT USAGE ON SCHEMA validation TO validation_ro';

  -- 공개 지표 뷰 12 + API 노출 뷰 2(v_api_attempt·v_api_alert_link)
  EXECUTE 'GRANT SELECT ON '
    || 'validation.v_metric_rates, validation.v_metric_mttd, validation.v_metric_correlation, '
    || 'validation.v_metric_h2, validation.v_metric_coverage, validation.v_metric_attacker, '
    || 'validation.v_metric_m07a, validation.v_metric_m13, validation.v_metric_m14a, '
    || 'validation.v_metric_m14b, validation.v_metric_m14_rule, validation.v_run_integrity, '
    || 'validation.v_api_attempt, validation.v_api_alert_link '
    || 'TO validation_ro';

  -- 적재/스냅샷/출처 테이블
  EXECUTE 'GRANT SELECT ON '
    || 'validation.measurement_run, validation.metric_snapshot, '
    || 'validation.metric_snapshot_withdrawal, validation.run_provenance_note '
    || 'TO validation_ro';

  -- PUBLIC EXECUTE 회수된 통계 함수 3개만 명시 부여(C7). compare_snapshots 는 부여 안 함 — API 는 직접 join.
  EXECUTE 'GRANT EXECUTE ON FUNCTION validation.wilson_ci(bigint, bigint) TO validation_ro';
  EXECUTE 'GRANT EXECUTE ON FUNCTION validation.quantile_t8(double precision[], double precision) TO validation_ro';
  EXECUTE 'GRANT EXECUTE ON FUNCTION validation.newcombe_diff_ci(bigint, bigint, bigint, bigint) TO validation_ro';
END $$;
