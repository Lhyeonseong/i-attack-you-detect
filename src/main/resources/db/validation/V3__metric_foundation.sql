-- validation schema v3 (S4-2) — 지표 기반 (ADR-S4-01 v1.2 R3·R10·R11·R12)
-- run_id NOT NULL 전환, Wilson 구간 함수, type 8 백분위 함수, 고정 범위 목록, R10 3상태 뷰.
-- 지표 뷰(M01~M10)는 이 함수·뷰 위에 따로 얹는다.

-- 1) 모든 verdict 는 하나의 run 에 귀속 (R10). 백필(RUNBOOK) 전이면 실패 — 전체 롤백, 행 보존.
DO
$$
DECLARE
    orphans bigint;
BEGIN
    SELECT count(*) INTO orphans FROM validation.verdict_result WHERE run_id IS NULL;
    IF orphans > 0 THEN
        RAISE EXCEPTION 'verdict_result run_id NULL %행 — run_id 백필을 먼저 끝낸 뒤 V3 를 적용한다', orphans;
    END IF;
END;
$$;

ALTER TABLE verdict_result ALTER COLUMN run_id SET NOT NULL;
COMMENT ON COLUMN verdict_result.run_id IS '측정 run (measurement_run), NOT NULL(V3) — 새 verdict INSERT 때만 채우고 갱신(UPDATE)은 최초 run 귀속 유지';

-- 2) R3 Wilson 95% 구간 (z = 1.959964). n = 0 → p·lo·hi 모두 NULL. I4: 0 ≤ lo ≤ p ≤ hi ≤ 1
CREATE FUNCTION wilson_ci(x bigint, n bigint)
    RETURNS TABLE (p double precision, lo double precision, hi double precision)
    LANGUAGE plpgsql IMMUTABLE STRICT AS
$$
DECLARE
    z      CONSTANT double precision := 1.959964;
    phat   double precision;
    denom  double precision;
    center double precision;
    half   double precision;
BEGIN
    IF n < 0 OR x < 0 OR x > n THEN
        RAISE EXCEPTION 'wilson_ci: 0 <= x <= n 이어야 한다 (x=%, n=%)', x, n
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF n = 0 THEN
        RETURN QUERY SELECT NULL::double precision, NULL::double precision, NULL::double precision;
        RETURN;
    END IF;
    phat := x::double precision / n;
    denom := 1 + z * z / n;
    center := (phat + z * z / (2 * n)) / denom;
    half := z * sqrt(phat * (1 - phat) / n + z * z / (4.0 * n * n)) / denom;
    -- 부동소수 오차로 [0,1]·점추정 밖으로 나가지 않게 고정 (x=0 → lo=0, x=n → hi=1)
    RETURN QUERY SELECT phat, greatest(0, least(phat, center - half)), least(1, greatest(phat, center + half));
END;
$$;
COMMENT ON FUNCTION wilson_ci(bigint, bigint) IS 'ADR-S4-01 R3: Wilson 95% 구간, z=1.959964. n=0 → NULL("해당 없음(n=0)"), 0<=x<=n 아니면 22023';

-- 3) R11 백분위 — Hyndman & Fan(1996) type 8 (R quantile type=8, NumPy median_unbiased). NULL 원소 제외, 빈 입력 → NULL
CREATE FUNCTION quantile_t8(vals double precision[], prob double precision)
    RETURNS double precision
    LANGUAGE plpgsql IMMUTABLE AS
$$
DECLARE
    xs double precision[];
    n  integer;
    h  double precision;
    j  integer;
BEGIN
    IF prob < 0 OR prob > 1 THEN
        RAISE EXCEPTION 'quantile_t8: 0 <= p <= 1 이어야 한다 (p=%)', prob
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT array_agg(v ORDER BY v) INTO xs FROM unnest(vals) AS v WHERE v IS NOT NULL;
    n := coalesce(cardinality(xs), 0);
    IF n = 0 OR prob IS NULL THEN
        RETURN NULL;
    END IF;
    h := (n + 1.0 / 3) * prob + 1.0 / 3;
    IF h <= 1 THEN
        RETURN xs[1];
    END IF;
    IF h >= n THEN
        RETURN xs[n];
    END IF;
    j := floor(h);
    RETURN xs[j] + (h - j) * (xs[j + 1] - xs[j]);
END;
$$;
COMMENT ON FUNCTION quantile_t8(double precision[], double precision) IS 'ADR-S4-01 R11: Hyndman & Fan type 8 표본 분위수. NULL 원소 제외, n=0 → NULL, p 범위 밖 → 22023. n 은 호출 쪽에서 병기';

REVOKE ALL ON FUNCTION wilson_ci(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION quantile_t8(double precision[], double precision) FROM PUBLIC;

-- 4) R12 고정 범위 목록 — M06a·M06b 분모. 변경은 ADR 개정(R7) + 새 마이그레이션으로만
CREATE TABLE metric_scope (
    kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    CONSTRAINT pk_metric_scope PRIMARY KEY (kind, unit),
    CONSTRAINT ck_metric_scope_kind CHECK (kind IN ('TECHNIQUE', 'SCENARIO'))
);
COMMENT ON TABLE metric_scope IS 'ADR-S4-01 R12: Analytic Coverage(M06a·M06b) 분모 범위 단위 — 시도 0건 단위도 분모에 포함';

INSERT INTO metric_scope (kind, unit) VALUES
    ('TECHNIQUE', 'T1190'),
    ('TECHNIQUE', 'T1110'),
    ('SCENARIO', 'SQLI'),
    ('SCENARIO', 'PATH_TRAVERSAL'),
    ('SCENARIO', 'BRUTE_FORCE'),
    ('SCENARIO', 'SSRF');

-- 5) R10 표본 무결성 3상태 — run 마다 1행(verdict 0건 run 포함). Java(MeasurementRunRecorder.integrity)도 이 뷰만 읽는다
CREATE VIEW v_run_integrity AS
SELECT x.run_id, x.label, x.kind, x.status,
       x.expected_attempts, x.expected_controls, x.actual_attack, x.actual_control,
       CASE
           WHEN x.r10_reason IS NULL THEN 'VALID'
           WHEN x.r10_reason = 'OPEN' THEN 'INCOMPLETE'
           ELSE 'INVALID'
       END AS r10_status,
       x.r10_reason
FROM (SELECT r.run_id, r.label, r.kind, r.status, r.expected_attempts, r.expected_controls,
             c.actual_attack, c.actual_control,
             CASE
                 WHEN r.status = 'OPEN' THEN 'OPEN'
                 WHEN r.expected_attempts IS NULL OR r.expected_controls IS NULL THEN 'EXPECTED_MISSING'
                 WHEN c.actual_attack <> r.expected_attempts THEN 'ATTACK_MISMATCH'
                 WHEN c.actual_control <> r.expected_controls THEN 'CONTROL_MISMATCH'
             END AS r10_reason
      FROM measurement_run r
      CROSS JOIN LATERAL (
          SELECT count(*) FILTER (WHERE v.attempt_role = 'ATTACK')  AS actual_attack,
                 count(*) FILTER (WHERE v.attempt_role = 'CONTROL') AS actual_control
          FROM verdict_result v
          WHERE v.run_id = r.run_id) c) x;

COMMENT ON VIEW v_run_integrity IS 'ADR-S4-01 R10: VALID = CLOSED ∧ ATTACK·CONTROL 실제 = 기대, INVALID = CLOSED ∧ (불일치 ∨ 기대 없음), INCOMPLETE = OPEN. '
    'r10_reason 은 첫 해당 1개, 우선순위 OPEN → EXPECTED_MISSING → ATTACK_MISMATCH → CONTROL_MISMATCH (VALID 는 NULL). 지표는 VALID run 에서만 산출';
COMMENT ON COLUMN v_run_integrity.r10_reason IS 'OPEN | EXPECTED_MISSING | ATTACK_MISMATCH | CONTROL_MISMATCH | NULL(VALID) — 우선순위 OPEN → EXPECTED_MISSING → ATTACK_MISMATCH → CONTROL_MISMATCH';
