package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T1 — validation.wilson_ci(x, n): ADR-S4-01 R3 (z = 1.959964, n=0 → NULL, I4)
 * 기대값 독립 검증: numpy 2.5.4 / statsmodels 0.15.0, detections/measurements/evidence/2026-10-18_s4-2-crosscheck.py·.log
 */
class WilsonCiTest extends ValidationDbFixture {

    private static final double TOL = 1e-5;

    private static Map<String, Object> ci(int x, int n) {
        return JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(?, ?)", x, n);
    }

    private static double d(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).doubleValue();
    }

    @Test
    void knownValues() {
        assertEquals(0.83887, d(ci(20, 20), "lo"), TOL);
        assertEquals(0.95418, d(ci(80, 80), "lo"), TOL);
        assertEquals(0.049992, d(ci(0, 73), "hi"), TOL);
        Map<String, Object> half = ci(10, 20);
        assertEquals(0.299298, d(half, "lo"), TOL);
        assertEquals(0.700702, d(half, "hi"), TOL);
        assertEquals(0.5, d(half, "p"), TOL);
    }

    @Test
    void zeroDenominatorIsAllNull() {
        Map<String, Object> row = ci(0, 0);
        assertNull(row.get("p"));
        assertNull(row.get("lo"));
        assertNull(row.get("hi"));
    }

    /** 입력 오류는 SQLSTATE 22023(invalid_parameter_value) — 함수 부재(42883) 등 다른 오류와 구분 */
    @Test
    void invalidInputRaises() {
        assertInvalidParameter(() -> ci(-1, 10));
        assertInvalidParameter(() -> ci(11, 10));
        assertInvalidParameter(() -> ci(0, -1));
    }

    static void assertInvalidParameter(Runnable call) {
        DataAccessException e = assertThrows(DataAccessException.class, call::run);
        java.sql.SQLException sql = (java.sql.SQLException) e.getMostSpecificCause();
        assertEquals("22023", sql.getSQLState(), sql.getMessage());
    }

    /** I4: n=1..100, x=0..n 전부 0 ≤ lo ≤ p ≤ hi ≤ 1 */
    @Test
    void invariantI4HoldsForAllSmallSamples() {
        Integer violations = JDBC.queryForObject("""
                SELECT count(*) FROM generate_series(1, 100) AS n
                CROSS JOIN LATERAL generate_series(0, n) AS x
                CROSS JOIN LATERAL validation.wilson_ci(x, n) AS w
                WHERE NOT (0 <= w.lo AND w.lo <= w.p AND w.p <= w.hi AND w.hi <= 1)
                   OR w.lo IS NULL OR w.p IS NULL OR w.hi IS NULL""", Integer.class);
        assertEquals(0, violations);
        Integer cases = JDBC.queryForObject(
                "SELECT count(*) FROM generate_series(1, 100) AS n CROSS JOIN LATERAL generate_series(0, n) AS x",
                Integer.class);
        assertTrue(cases == 5150, "검사 케이스 수: " + cases);
    }
}
