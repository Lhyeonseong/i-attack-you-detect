package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.units;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * T4 — validation.v_metric_mttd (M04, R11 type 8, SUCCEEDED_DETECTED ∧ late=false 만 — 늦은 탐지는 M10).
 * F1: ALL {1000,2000,3000,5000}, SQLI {1000,2000,3000}, PT 는 late 1건뿐이라 n=0.
 */
class MttdViewTest extends ValidationDbFixture {

    private UUID run;

    @BeforeEach
    void fixtures() {
        truncateRunData();
        run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
    }

    private Map<String, Object> mttd(String kind, String unit) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_mttd WHERE run_id = ? AND split_kind = ? "
                + "AND split_unit = ?", run, kind, unit);
    }

    private void assertMttd(String kind, String unit, long n, double p50, double p95) {
        Map<String, Object> row = mttd(kind, unit);
        assertEquals(n, l(row, "n"), unit);
        assertEquals(p50, d(row, "p50_ms"), 1e-9, unit + " p50");
        assertEquals(p95, d(row, "p95_ms"), 1e-9, unit + " p95");
        assertEquals("OK", row.get("status"), unit);
        assertEquals(MetricFixture.DEF_VERSION, row.get("definition_version"));
    }

    @Test
    void percentilesOfOnTimeDetections() {
        assertMttd("ALL", "ALL", 4, 2500, 5000);
        assertMttd("SCENARIO", "SQLI", 3, 2000, 3000);
        assertMttd("SCENARIO", "UNKNOWN", 1, 5000, 5000);
        assertMttd("TECHNIQUE", "T1190", 4, 2500, 5000);
    }

    @Test
    void lateDetectionIsExcludedAndEmptyUnitsAreNoData() {
        for (String[] unit : List.of(new String[] {"SCENARIO", "PATH_TRAVERSAL"}, new String[] {"SCENARIO", "BRUTE_FORCE"},
                new String[] {"SCENARIO", "SSRF"}, new String[] {"TECHNIQUE", "T1110"})) {
            Map<String, Object> row = mttd(unit[0], unit[1]);
            assertEquals(0L, l(row, "n"), unit[1]);
            assertNull(row.get("p50_ms"), unit[1]);
            assertNull(row.get("p95_ms"), unit[1]);
            assertEquals("NO_DATA", row.get("status"), unit[1]);
        }
    }

    /** D1 행 집합: ALL + 시나리오 4종 + UNKNOWN(시도 있음) + 기법 2종 */
    @Test
    void rowSet() {
        assertEquals(List.of("ALL:ALL", "SCENARIO:BRUTE_FORCE", "SCENARIO:PATH_TRAVERSAL", "SCENARIO:SQLI",
                        "SCENARIO:SSRF", "SCENARIO:UNKNOWN", "TECHNIQUE:T1110", "TECHNIQUE:T1190"),
                units(JDBC.queryForList("SELECT * FROM validation.v_metric_mttd WHERE run_id = ?", run)));
    }
}
