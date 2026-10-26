package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * T2 — validation.quantile_t8(vals, p): ADR-S4-01 R11 (Hyndman & Fan type 8, n=0 → NULL)
 * 기대값 독립 검증: numpy 2.5.4 / statsmodels 0.15.0, detections/measurements/evidence/2026-10-18_s4-2-crosscheck.py·.log
 */
class QuantileType8Test extends ValidationDbFixture {

    private static final double TOL = 1e-9;

    private static Double q(String arrayLiteral, double p) {
        return JDBC.queryForObject("SELECT validation.quantile_t8(" + arrayLiteral + "::double precision[], ?)",
                Double.class, p);
    }

    private static final String ONE_TO_20 = "ARRAY(SELECT generate_series(1, 20))";

    @Test
    void knownValues() {
        assertEquals(10.5, q(ONE_TO_20, 0.5), TOL);
        assertEquals(19.65, q(ONE_TO_20, 0.95), TOL);
        assertEquals(5.0, q("'{1,2,3,4,5}'", 0.95), TOL);
        for (double p : new double[] {0.0, 0.01, 0.5, 0.95, 0.99, 1.0}) {
            assertEquals(7.0, q("'{7}'", p), TOL, "단일 원소 p=" + p);
        }
    }

    @Test
    void emptyOrNullIsNull() {
        assertNull(q("'{}'", 0.5));
        assertNull(q("NULL", 0.5));
        assertNull(q("'{NULL,NULL}'", 0.5), "NULL 원소는 제외 → 빈 배열");
    }

    @Test
    void nullElementsAreIgnored() {
        assertEquals(5.0, q("'{1,NULL,2,3,4,5}'", 0.95), TOL);
    }

    @Test
    void unsortedInputGivesSameResult() {
        assertEquals(19.65, q("'{20,3,17,1,9,12,5,19,2,14,8,6,16,11,4,18,13,10,7,15}'", 0.95), TOL);
        assertEquals(10.5, q("'{20,3,17,1,9,12,5,19,2,14,8,6,16,11,4,18,13,10,7,15}'", 0.5), TOL);
    }

    @Test
    void probabilityOutsideUnitIntervalRaises() {
        WilsonCiTest.assertInvalidParameter(() -> q("'{1,2,3}'", -0.01));
        WilsonCiTest.assertInvalidParameter(() -> q("'{1,2,3}'", 1.01));
    }
}
