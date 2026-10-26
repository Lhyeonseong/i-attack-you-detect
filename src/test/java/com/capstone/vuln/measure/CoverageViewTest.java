package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * T6 — validation.v_metric_coverage (M06a·M06b) · v_metric_coverage_unit (단위별 상세).
 * 분모 = metric_scope 고정 목록(R12), UNKNOWN 은 단위가 아니다.
 * M06a 분자 = SUCCEEDED_DETECTED ≥1 (최종 verdict — PT 늦은 탐지 포함, R5),
 * M06b 분자 = S_ALL ≥1 ∧ SUCCEEDED_MISSED = 0 (D2 — SSRF 는 S_ALL=0 이라 제외).
 */
class CoverageViewTest extends ValidationDbFixture {

    private UUID run;

    @BeforeEach
    void fixtures() {
        truncateRunData();
        run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
    }

    private Map<String, Object> coverage(String metric, String kind) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_coverage WHERE run_id = ? AND metric_id = ? "
                + "AND split_kind = ?", run, metric, kind);
    }

    @Test
    void techniqueCoverage() {
        assertEquals("1/2", xn(coverage("M06a", "TECHNIQUE")));
        assertEquals("0/2", xn(coverage("M06b", "TECHNIQUE")));
    }

    @Test
    void scenarioCoverage() {
        assertEquals("2/4", xn(coverage("M06a", "SCENARIO")));
        assertEquals("1/4", xn(coverage("M06b", "SCENARIO")));
    }

    @Test
    void coverageRowsCarryWilsonAndVersion() {
        List<Map<String, Object>> rows = JDBC.queryForList(
                "SELECT * FROM validation.v_metric_coverage WHERE run_id = ?", run);
        assertEquals(4, rows.size());
        for (Map<String, Object> row : rows) {
            assertEquals(MetricFixture.DEF_VERSION, row.get("definition_version"));
            assertEquals("OK", row.get("status"), row.toString());
            Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(?, ?)",
                    l(row, "x"), l(row, "n"));
            for (String k : List.of("p", "lo", "hi")) {
                assertEquals(d(ci, k), d(row, k), 1e-12, row + " " + k);
            }
        }
    }

    /** unit → s_all, sd, sm, present, consistent */
    @Test
    void perUnitDetail() {
        List<Map<String, Object>> rows = JDBC.queryForList("""
                SELECT split_kind, split_unit, s_all, sd, sm, present, consistent, definition_version
                FROM validation.v_metric_coverage_unit WHERE run_id = ? ORDER BY split_kind, split_unit""", run);
        assertEquals(List.of(
                "SCENARIO:BRUTE_FORCE 1 0 1 false false",
                "SCENARIO:PATH_TRAVERSAL 1 1 0 true true",
                "SCENARIO:SQLI 4 3 1 true false",
                "SCENARIO:SSRF 0 0 0 false false",
                "TECHNIQUE:T1110 1 0 1 false false",
                "TECHNIQUE:T1190 6 5 1 true false"),
                rows.stream().map(r -> r.get("split_kind") + ":" + r.get("split_unit") + " " + l(r, "s_all") + " "
                        + l(r, "sd") + " " + l(r, "sm") + " " + r.get("present") + " " + r.get("consistent")).toList());
        rows.forEach(r -> assertEquals(MetricFixture.DEF_VERSION, r.get("definition_version")));
    }
}
