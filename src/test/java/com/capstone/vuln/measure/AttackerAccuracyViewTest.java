package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * T7 — validation.v_metric_attacker (M09, 시나리오별). 같은 픽스처에서 뷰 = GateEvaluator(단일 원천).
 * 기준(결정3, 점추정): 일치율 ≥ 0.95 ∧ 과대평가 0 ∧ conclusive n ≥ 20 → criteria_met. Wilson 은 병기만.
 * D3: criteria_met 은 측정값이며 게이트 전환 판정 기록이 아니다.
 */
class AttackerAccuracyViewTest extends ValidationDbFixture {

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    /** SQLI 20/20 PASS · PT 19/20(과소평가 1) 경계 PASS · BF n=19 미달 · SSRF 19/20 + 과대평가 1 → 미충족 */
    private static UUID criteriaRun() {
        return new MetricFixture(JDBC)
                .add(20, a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("SQLI", "T1190", "UNCERTAIN"))
                .add(19, a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_MISSED").attacker("FAILED", false, false))
                .add(19, a("BRUTE_FORCE", "T1110", "SUCCEEDED_MISSED"))
                .add(19, a("SSRF", "T1190", "SUCCEEDED_DETECTED"))
                .add(a("SSRF", "T1190", "FAILED_UNSEEN").attacker("SUCCEEDED", false, true))
                .close(MetricFixture.Close.VALID);
    }

    private static Map<String, Object> view(UUID run, String scenario) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_attacker WHERE run_id = ? AND split_unit = ?",
                run, scenario);
    }

    private static void assertViewEqualsGate(UUID run) {
        GateReport gate = GateEvaluator.evaluate(new GateVerdictReader(DS).loadSamples(run), Instant.EPOCH);
        Set<String> seen = new HashSet<>();
        for (ScenarioGate g : gate.scenarios()) {
            Map<String, Object> row = view(run, g.scenario());
            String s = g.scenario();
            assertEquals(g.samples(), l(row, "n"), s + " conclusive n");
            assertEquals(g.matchRate(), d(row, "p"), 1e-12, s + " match rate");
            assertEquals(g.overestimateCount(), l(row, "overestimate"), s + " overestimate");
            assertEquals(g.uncertainCount(), l(row, "uncertain"), s + " uncertain");
            assertEquals(g.result() == GateResult.PASS, row.get("criteria_met"), s + " criteria_met");
            seen.add(s);
        }
        // 게이트에 행이 없는 시나리오(시도 0건) = n=0 NO_DATA, 기준 미충족
        for (Map<String, Object> row : JDBC.queryForList(
                "SELECT * FROM validation.v_metric_attacker WHERE run_id = ?", run)) {
            assertEquals(MetricFixture.DEF_VERSION, row.get("definition_version"));
            if (!seen.contains((String) row.get("split_unit"))) {
                assertEquals(0L, l(row, "n"), row.toString());
                assertNull(row.get("p"), row.toString());
                assertEquals("NO_DATA", row.get("status"), row.toString());
                assertEquals(false, row.get("criteria_met"), row.toString());
            }
        }
    }

    @Test
    void f1ViewEqualsGateEvaluator() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        assertViewEqualsGate(run);
        Map<String, Object> sqli = view(run, "SQLI");
        assertEquals(5L, l(sqli, "n"));
        assertEquals(4L, l(sqli, "x"));
        assertEquals(1L, l(sqli, "overestimate"));
        assertFalse((Boolean) sqli.get("criteria_met"));
        assertEquals(List.of("BRUTE_FORCE", "PATH_TRAVERSAL", "SQLI", "SSRF", "UNKNOWN"),
                JDBC.queryForList("SELECT split_unit FROM validation.v_metric_attacker WHERE run_id = ? "
                        + "ORDER BY split_unit", String.class, run));
    }

    @Test
    void criteriaBoundariesEqualGateEvaluator() {
        UUID run = criteriaRun();
        assertViewEqualsGate(run);
        assertEquals(true, view(run, "SQLI").get("criteria_met"));
        assertEquals(true, view(run, "PATH_TRAVERSAL").get("criteria_met"));
        assertEquals(false, view(run, "BRUTE_FORCE").get("criteria_met"));
        assertEquals(false, view(run, "SSRF").get("criteria_met"));
    }

    /** Wilson 병기 — 기준에는 쓰지 않는다 */
    @Test
    void matchRateCarriesWilson() {
        UUID run = criteriaRun();
        Map<String, Object> pt = view(run, "PATH_TRAVERSAL");
        Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(19, 20)");
        assertEquals(19L, l(pt, "x"));
        for (String k : List.of("p", "lo", "hi")) {
            assertEquals(d(ci, k), d(pt, k), 1e-12, k);
        }
        assertEquals("OK", pt.get("status"));
    }
}
