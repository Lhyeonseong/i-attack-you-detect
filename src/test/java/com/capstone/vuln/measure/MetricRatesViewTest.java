package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.rate;
import static com.capstone.vuln.measure.MetricFixture.rates;
import static com.capstone.vuln.measure.MetricFixture.units;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T1~T3 — validation.v_metric_rates (ADR-S4-01 v1.4 M01·M02·M03·M07b·M08·M10·M12, R2·R3·R5·R6·R8·D1·D4·D5).
 * x/n 기대값 = 픽스처 F1 손계산(현성 확인). 구간은 V3 wilson_ci(statsmodels 독립 검증)와 같은지만 본다.
 */
class MetricRatesViewTest extends ValidationDbFixture {

    private static final List<String> SCENARIOS = List.of("SQLI", "PATH_TRAVERSAL", "BRUTE_FORCE", "SSRF", "UNKNOWN");
    private static final List<String> TECHNIQUES = List.of("T1190", "T1110");

    private UUID run;

    @BeforeEach
    void fixtures() {
        truncateRunData();
        run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
    }

    /** 열 순서: ALL / SQLI / PT / BF / SSRF / UNKNOWN // T1190 / T1110 */
    private void assertSplits(String metric, String all, String sqli, String pt, String bf, String ssrf, String unknown,
                              String t1190, String t1110) {
        assertXn(metric, "ALL", "ALL", all);
        List<String> scenarioExpected = List.of(sqli, pt, bf, ssrf, unknown);
        for (int i = 0; i < SCENARIOS.size(); i++) {
            assertXn(metric, "SCENARIO", SCENARIOS.get(i), scenarioExpected.get(i));
        }
        if (t1190 != null) {
            assertXn(metric, "TECHNIQUE", "T1190", t1190);
            assertXn(metric, "TECHNIQUE", "T1110", t1110);
        }
    }

    private void assertXn(String metric, String kind, String unit, String expected) {
        assertEquals(expected, xn(rate(JDBC, run, metric, kind, unit)), metric + " " + kind + ":" + unit);
    }

    @Test
    void m01AttackSuccessRate() {
        assertSplits("M01", "7/10", "4/5", "1/3", "1/1", "0/0", "1/1", "6/9", "1/1");
    }

    @Test
    void m02DetectionRate() {
        assertSplits("M02", "5/7", "3/4", "1/1", "0/1", "0/0", "1/1", "5/6", "0/1");
    }

    @Test
    void m03MissRate() {
        assertSplits("M03", "2/7", "1/4", "0/1", "1/1", "0/0", "0/1", "1/6", "1/1");
    }

    /** R5: 최종 verdict 가 주 값, initial_verdict 기준 값은 보조 병기 (PT 늦은 탐지 1건이 initial 에선 MISSED) */
    @Test
    void m02m03InitialVerdictBasis() {
        assertSplits("M02_INITIAL", "4/7", "3/4", "0/1", "0/1", "0/0", "1/1", "4/6", "0/1");
        assertSplits("M03_INITIAL", "3/7", "1/4", "1/1", "1/1", "0/0", "0/1", "2/6", "1/1");
    }

    /**
     * D4: 보조값은 분자·분모 모두 initial 기준. initial=SUCCEEDED_MISSED → 최종 UNCERTAIN(늦은 저신뢰 링크) 1건이
     * 혼합 정의였다면 분자에만 들어가 x > n(wilson_ci 22023) — initial 기준이면 M03_INITIAL 분자·분모에 함께 들어가고
     * 최종 M03 에는 없다.
     */
    @Test
    void initialBasisUsesInitialDenominator() {
        UUID small = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("SQLI", "T1190", "UNCERTAIN").initial("SUCCEEDED_MISSED"))
                .close(MetricFixture.Close.VALID);
        assertEquals("1/2", xn(rate(JDBC, small, "M03_INITIAL", "ALL", "ALL")));
        assertEquals("1/2", xn(rate(JDBC, small, "M02_INITIAL", "ALL", "ALL")));
        assertEquals("0/1", xn(rate(JDBC, small, "M03", "ALL", "ALL")));
        assertEquals("1/1", xn(rate(JDBC, small, "M02", "ALL", "ALL")));
        for (Map<String, Object> row : JDBC.queryForList(
                "SELECT * FROM validation.v_metric_rates WHERE run_id = ? AND metric_id <> 'M12'", small)) {
            assertTrue(l(row, "x") <= l(row, "n"), row.toString());
        }
    }

    @Test
    void m07bAttemptUnseenRateIsScenarioOnly() {
        assertXn("M07b", "SCENARIO", "SQLI", "1/1");
        assertXn("M07b", "SCENARIO", "PATH_TRAVERSAL", "1/2");
        assertXn("M07b", "SCENARIO", "BRUTE_FORCE", "0/0");
        assertXn("M07b", "SCENARIO", "SSRF", "0/0");
        assertXn("M07b", "SCENARIO", "UNKNOWN", "0/0");
        assertEquals(SCENARIOS.stream().map(s -> "SCENARIO:" + s).sorted().toList(), units(rates(JDBC, run, "M07b")));
    }

    @Test
    void m08UncertainRate() {
        assertSplits("M08", "1/11", "1/6", "0/3", "0/1", "0/0", "0/1", "1/10", "0/1");
    }

    @Test
    void m10LateDetection() {
        assertSplits("M10", "1/6", "0/3", "1/2", "0/0", "0/0", "0/1", null, null);
    }

    /** D1: 범위 6단위는 n=0 이어도 표시, UNKNOWN 은 시도 1건 이상일 때만. ADR 분할(카드) 밖 행은 없다 */
    @Test
    void rowSetFollowsD1AndMetricCards() {
        List<String> scenarioRows = SCENARIOS.stream().map(s -> "SCENARIO:" + s).toList();
        List<String> techniqueRows = TECHNIQUES.stream().map(t -> "TECHNIQUE:" + t).toList();
        List<String> full = sorted(List.of("ALL:ALL"), scenarioRows, techniqueRows);
        List<String> allAndScenario = sorted(List.of("ALL:ALL"), scenarioRows);
        for (String m : List.of("M01", "M02", "M03", "M02_INITIAL", "M03_INITIAL", "M08")) {
            assertEquals(full, units(rates(JDBC, run, m)), m);
        }
        assertEquals(allAndScenario, units(rates(JDBC, run, "M10")));
        assertEquals(List.of("ALL:ALL"), units(rates(JDBC, run, "M12")));
        assertEquals(List.of("M01", "M02", "M02_INITIAL", "M03", "M03_INITIAL", "M07b", "M08", "M10", "M12"),
                JDBC.queryForList("SELECT DISTINCT metric_id FROM validation.v_metric_rates WHERE run_id = ? "
                        + "ORDER BY metric_id", String.class, run));
    }

    @Test
    void unknownRowsOnlyWhenTheRunHasUnknownAttempts() {
        UUID noUnknown = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .close(MetricFixture.Close.VALID);
        List<String> expected = sorted(List.of("ALL:ALL"),
                List.of("SCENARIO:SQLI", "SCENARIO:PATH_TRAVERSAL", "SCENARIO:BRUTE_FORCE", "SCENARIO:SSRF"),
                List.of("TECHNIQUE:T1190", "TECHNIQUE:T1110"));
        assertEquals(expected, units(rates(JDBC, noUnknown, "M01")));
        Map<String, Object> ssrf = rate(JDBC, noUnknown, "M01", "SCENARIO", "SSRF");
        assertEquals("0/0", xn(ssrf));
        assertEquals("NO_DATA", ssrf.get("status"));
    }

    /** T2: n=0 → p·lo·hi NULL, NO_DATA (0% 금지, R3). M12 = N/A 1행, 수치 전부 NULL (R8) */
    @Test
    void zeroDenominatorIsNoDataAndBlockRateIsNotApplicable() {
        Map<String, Object> ssrf = rate(JDBC, run, "M02", "SCENARIO", "SSRF");
        assertEquals("NO_DATA", ssrf.get("status"));
        assertNull(ssrf.get("p"));
        assertNull(ssrf.get("lo"));
        assertNull(ssrf.get("hi"));

        for (Map<String, Object> row : JDBC.queryForList(
                "SELECT * FROM validation.v_metric_rates WHERE run_id = ? AND metric_id <> 'M12'", run)) {
            boolean empty = l(row, "n") == 0;
            assertEquals(empty ? "NO_DATA" : "OK", row.get("status"), row.toString());
            if (empty) {
                assertEquals(0L, l(row, "x"), row.toString());
                assertNull(row.get("p"), row.toString());
                assertNull(row.get("lo"), row.toString());
                assertNull(row.get("hi"), row.toString());
            }
        }

        List<Map<String, Object>> m12 = rates(JDBC, run, "M12");
        assertEquals(1, m12.size());
        Map<String, Object> na = m12.get(0);
        assertEquals("NOT_APPLICABLE", na.get("status"));
        for (String k : List.of("x", "n", "p", "lo", "hi")) {
            assertNull(na.get(k), "M12 " + k);
        }
    }

    /** T3: OK 행 (p, lo, hi) = validation.wilson_ci(x, n), 모든 행 definition_version 고정 */
    @Test
    void okRowsCarryWilsonInterval() {
        List<Map<String, Object>> rows = JDBC.queryForList(
                "SELECT * FROM validation.v_metric_rates WHERE run_id = ?", run);
        int ok = 0;
        for (Map<String, Object> row : rows) {
            assertEquals(MetricFixture.DEF_VERSION, row.get("definition_version"), row.toString());
            if (!"OK".equals(row.get("status"))) {
                continue;
            }
            ok++;
            Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(?, ?)",
                    l(row, "x"), l(row, "n"));
            for (String k : List.of("p", "lo", "hi")) {
                assertEquals(d(ci, k), d(row, k), 1e-12, row + " " + k);
            }
        }
        assertTrue(ok > 0);
    }

    @SafeVarargs
    private static List<String> sorted(List<String>... parts) {
        return java.util.Arrays.stream(parts).flatMap(List::stream).sorted().toList();
    }
}
