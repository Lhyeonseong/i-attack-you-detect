package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.rate;
import static com.capstone.vuln.measure.MetricFixture.rates;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T8 — ADR-S4-01 정합성 불변식 I1·I3·I5·I6 (v1.4).
 * I6 검증 기준 = M08(분모가 전체 시도인 유일한 지표, D5) — 시나리오·기법 합 모두. M01~M03·M10 합은 보조로 같이 본다.
 */
class InvariantTest extends ValidationDbFixture {

    private static final List<String> STABLE_UNDER_UNCERTAIN =
            List.of("M01", "M02", "M03", "M02_INITIAL", "M03_INITIAL", "M07b", "M10");

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    /** SQLI/T1190 1 + 시나리오·기법 NULL 1 + 'UNKNOWN'/T1059(범위 밖 기법) 1 + 범위 밖 시나리오 XSS/T1190 1 */
    private static UUID unknownsRun() {
        return new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .add(a(null, null, "SUCCEEDED_MISSED"))
                .add(a("UNKNOWN", "T1059", "FAILED_UNSEEN"))
                .add(a("XSS", "T1190", "UNCERTAIN"))
                .close(MetricFixture.Close.VALID);
    }

    @Test
    void i1DetectionPlusMissIsOne() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        for (String[] pair : List.of(new String[] {"M02", "M03"}, new String[] {"M02_INITIAL", "M03_INITIAL"})) {
            int checked = 0;
            for (Map<String, Object> det : rates(JDBC, run, pair[0])) {
                Map<String, Object> miss = rate(JDBC, run, pair[1], (String) det.get("split_kind"),
                        (String) det.get("split_unit"));
                assertEquals(l(det, "n"), l(miss, "n"), det.toString());
                if (l(det, "n") == 0) {
                    continue;
                }
                assertEquals(l(det, "n"), l(det, "x") + l(miss, "x"), det.toString());
                assertEquals(1.0, d(det, "p") + d(miss, "p"), 1e-12, det.toString());
                checked++;
            }
            assertTrue(checked > 0, pair[0]);
        }
    }

    @Test
    void i3AddingUncertainOnlyMovesM08AndM05() {
        UUID base = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        UUID plus = MetricFixture.f1(JDBC)
                .add(a("SQLI", "T1190", "UNCERTAIN").links("RID"))
                .close(MetricFixture.Close.VALID);

        for (String m : STABLE_UNDER_UNCERTAIN) {
            assertEquals(xnByUnit(base, m), xnByUnit(plus, m), m);
        }
        assertEquals(JDBC.queryForList("SELECT split_kind, split_unit, n, p50_ms, p95_ms FROM validation.v_metric_mttd "
                        + "WHERE run_id = ? ORDER BY 1, 2", base),
                JDBC.queryForList("SELECT split_kind, split_unit, n, p50_ms, p95_ms FROM validation.v_metric_mttd "
                        + "WHERE run_id = ? ORDER BY 1, 2", plus));
        assertEquals(JDBC.queryForList("SELECT metric_id, split_kind, x, n FROM validation.v_metric_coverage "
                        + "WHERE run_id = ? ORDER BY 1, 2", base),
                JDBC.queryForList("SELECT metric_id, split_kind, x, n FROM validation.v_metric_coverage "
                        + "WHERE run_id = ? ORDER BY 1, 2", plus));

        Map<String, String> m08Base = xnByUnit(base, "M08");
        Map<String, String> m08Plus = xnByUnit(plus, "M08");
        assertEquals("1/11", m08Base.get("ALL:ALL"));
        assertEquals("2/12", m08Plus.get("ALL:ALL"));
        assertEquals("1/6", m08Base.get("SCENARIO:SQLI"));
        assertEquals("2/7", m08Plus.get("SCENARIO:SQLI"));
        assertEquals("1/10", m08Base.get("TECHNIQUE:T1190"));
        assertEquals("2/11", m08Plus.get("TECHNIQUE:T1190"));
        List<String> moved = List.of("ALL:ALL", "SCENARIO:SQLI", "TECHNIQUE:T1190");
        m08Base.keySet().stream().filter(k -> !moved.contains(k))
                .forEach(k -> assertEquals(m08Base.get(k), m08Plus.get(k), "M08 " + k));

        assertEquals(0L, l(JDBC.queryForMap("SELECT n FROM validation.v_metric_h2 WHERE run_id = ?", base), "n"));
        assertEquals(1L, l(JDBC.queryForMap("SELECT n FROM validation.v_metric_h2 WHERE run_id = ?", plus), "n"));
    }

    @Test
    void i5ConsistentCoverageNeverExceedsPresence() {
        UUID f1 = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        UUID allGood = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_DETECTED"))
                .close(MetricFixture.Close.VALID);
        for (UUID run : List.of(f1, allGood, unknownsRun())) {
            for (String kind : List.of("TECHNIQUE", "SCENARIO")) {
                long present = l(coverage(run, "M06a", kind), "x");
                long consistent = l(coverage(run, "M06b", kind), "x");
                assertTrue(consistent <= present, run + " " + kind + " M06b=" + consistent + " M06a=" + present);
            }
        }
        assertEquals("2/2", xn(coverage(allGood, "M06b", "TECHNIQUE")));
        assertEquals("2/4", xn(coverage(allGood, "M06b", "SCENARIO")));
    }

    @Test
    void i6SplitsSumToAll() {
        UUID f1 = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        UUID unknowns = unknownsRun();
        for (UUID run : List.of(f1, unknowns)) {
            for (String m : List.of("M01", "M02", "M03", "M08", "M10")) {
                assertEquals(allN(run, m), splitSum(run, m, "SCENARIO"), run + " " + m + " Σscenario");
            }
            for (String m : List.of("M08", "M01", "M02", "M03")) {
                assertEquals(allN(run, m), splitSum(run, m, "TECHNIQUE"), run + " " + m + " Σtechnique");
            }
        }
        assertEquals(11L, allN(f1, "M08"));
        assertEquals(11L, splitSum(f1, "M08", "TECHNIQUE"));
        // NULL·'UNKNOWN'·범위 밖 시나리오 → UNKNOWN 1행, NULL·범위 밖 기법 → UNKNOWN 1행
        assertEquals("1/3", xn(rate(JDBC, unknowns, "M08", "SCENARIO", "UNKNOWN")));
        assertEquals("1/2", xn(rate(JDBC, unknowns, "M01", "TECHNIQUE", "UNKNOWN")));
        assertEquals("1/4", xn(rate(JDBC, unknowns, "M08", "ALL", "ALL")));
        assertEquals("0/2", xn(rate(JDBC, unknowns, "M08", "TECHNIQUE", "UNKNOWN")));
    }

    /** D6: 범위 밖 scenario 'FOO' 1건 + NULL 1건 → UNKNOWN 1행에 합산(FOO 행 없음), I6 성립 */
    @Test
    void outOfScopeAndNullScenarioFoldIntoOneUnknownRow() {
        UUID run = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("FOO", "T1190", "SUCCEEDED_MISSED"))
                .add(a(null, "T1190", "UNCERTAIN"))
                .close(MetricFixture.Close.VALID);
        List<String> scenarioUnits = rates(JDBC, run, "M08").stream()
                .filter(r -> "SCENARIO".equals(r.get("split_kind")))
                .map(r -> (String) r.get("split_unit")).sorted().toList();
        assertEquals(List.of("BRUTE_FORCE", "PATH_TRAVERSAL", "SQLI", "SSRF", "UNKNOWN"), scenarioUnits);
        assertEquals("1/2", xn(rate(JDBC, run, "M08", "SCENARIO", "UNKNOWN")));
        assertEquals("1/1", xn(rate(JDBC, run, "M01", "SCENARIO", "UNKNOWN")));
        assertEquals(3L, allN(run, "M08"));
        assertEquals(3L, splitSum(run, "M08", "SCENARIO"));
        assertEquals(3L, splitSum(run, "M08", "TECHNIQUE"));
    }

    private static Map<String, Object> coverage(UUID run, String metric, String kind) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_coverage WHERE run_id = ? AND metric_id = ? "
                + "AND split_kind = ?", run, metric, kind);
    }

    private static Map<String, String> xnByUnit(UUID run, String metric) {
        Map<String, String> out = new HashMap<>();
        for (Map<String, Object> r : rates(JDBC, run, metric)) {
            out.put(r.get("split_kind") + ":" + r.get("split_unit"), xn(r));
        }
        return out;
    }

    private static long allN(UUID run, String metric) {
        return l(rate(JDBC, run, metric, "ALL", "ALL"), "n");
    }

    private static long splitSum(UUID run, String metric, String kind) {
        return rates(JDBC, run, metric).stream().filter(r -> kind.equals(r.get("split_kind")))
                .mapToLong(r -> l(r, "n")).sum();
    }
}
