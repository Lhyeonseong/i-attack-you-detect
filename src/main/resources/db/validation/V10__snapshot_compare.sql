-- validation schema v10 (S5) — Before/After 스냅샷 비교 (ADR-S5-01)
-- 지표 정의·뷰·테이블은 바꾸지 않는다. 불변 metric_snapshot 끼리 두 독립 비율 차의 Newcombe 95% 구간을 계산하는 함수만 추가.
-- newcombe_diff_ci: Newcombe(1998) method 10(square-and-add, MOVER-Wilson). 기존 wilson_ci(z=1.959964) 재사용.
-- compare_snapshots: before/after run 의 metric×scope 를 묶어 (x1,n1)=after, (x2,n2)=before 로 diff·lo·hi.

-- (x1,n1)=after, (x2,n2)=before. diff = p1 - p2. n1=0 또는 n2=0 이면 NULL(해당 없음).
CREATE FUNCTION newcombe_diff_ci(x1 bigint, n1 bigint, x2 bigint, n2 bigint)
    RETURNS TABLE (diff double precision, lo double precision, hi double precision)
    LANGUAGE plpgsql IMMUTABLE STRICT AS
$$
DECLARE
    p1 double precision; l1 double precision; u1 double precision;
    p2 double precision; l2 double precision; u2 double precision;
BEGIN
    IF n1 = 0 OR n2 = 0 THEN
        RETURN QUERY SELECT NULL::double precision, NULL::double precision, NULL::double precision;
        RETURN;
    END IF;
    SELECT w.p, w.lo, w.hi INTO p1, l1, u1 FROM validation.wilson_ci(x1, n1) w;   -- x>n 이면 wilson_ci 가 거부
    SELECT w.p, w.lo, w.hi INTO p2, l2, u2 FROM validation.wilson_ci(x2, n2) w;
    RETURN QUERY SELECT
        p1 - p2,
        (p1 - p2) - sqrt((p1 - l1) * (p1 - l1) + (u2 - p2) * (u2 - p2)),
        (p1 - p2) + sqrt((u1 - p1) * (u1 - p1) + (p2 - l2) * (p2 - l2));
END;
$$;
COMMENT ON FUNCTION newcombe_diff_ci(bigint, bigint, bigint, bigint) IS
    'ADR-S5-01: 두 독립 비율 차(p1=after − p2=before)의 Newcombe 95% 구간(method 10, square-and-add, wilson_ci 재사용). n=0 → NULL';
REVOKE ALL ON FUNCTION newcombe_diff_ci(bigint, bigint, bigint, bigint) FROM PUBLIC;

-- before/after 두 run 의 스냅샷을 metric_id·scope 로 묶어 비교. definition_version 이 한 쌍이라도 다르면 거부.
CREATE FUNCTION compare_snapshots(p_before uuid, p_after uuid)
    RETURNS TABLE (metric_id text, scope_kind text, scope_key text,
                   x1 bigint, n1 bigint, x2 bigint, n2 bigint,
                   diff double precision, lo double precision, hi double precision)
    LANGUAGE plpgsql STABLE AS
$$
BEGIN
    IF EXISTS (
        SELECT 1 FROM validation.metric_snapshot a
        JOIN validation.metric_snapshot b
          ON a.metric_id = b.metric_id AND a.scope_kind = b.scope_kind AND a.scope_key = b.scope_key
        WHERE a.run_id = p_after AND b.run_id = p_before
          AND a.definition_version IS DISTINCT FROM b.definition_version) THEN
        RAISE EXCEPTION 'compare_snapshots: before/after definition_version 불일치 — 비교 거부 (ADR-S5-01, R13 e)'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN QUERY
        SELECT a.metric_id, a.scope_kind, a.scope_key,
               a.numerator, a.denominator, b.numerator, b.denominator,
               d.diff, d.lo, d.hi
        FROM validation.metric_snapshot a
        JOIN validation.metric_snapshot b
          ON a.metric_id = b.metric_id AND a.scope_kind = b.scope_kind AND a.scope_key = b.scope_key
        LEFT JOIN LATERAL validation.newcombe_diff_ci(a.numerator, a.denominator, b.numerator, b.denominator) d ON true
        WHERE a.run_id = p_after AND b.run_id = p_before
        ORDER BY a.metric_id, a.scope_kind, a.scope_key;
END;
$$;
COMMENT ON FUNCTION compare_snapshots(uuid, uuid) IS
    'ADR-S5-01: before/after 스냅샷 metric×scope 비교((x1,n1)=after, (x2,n2)=before, Newcombe 95%). definition_version 다르면 거부';
REVOKE ALL ON FUNCTION compare_snapshots(uuid, uuid) FROM PUBLIC;
