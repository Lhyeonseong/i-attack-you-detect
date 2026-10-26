package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GateEvaluatorTest {

    private static final Instant NOW = Instant.parse("2026-10-16T00:00:00Z");

    private static VerdictSample sample(String scenario, boolean uncertain, Boolean match, boolean overestimate) {
        return new VerdictSample(scenario, uncertain, match, overestimate);
    }

    private static List<VerdictSample> repeat(String scenario, int n, Boolean match) {
        List<VerdictSample> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(sample(scenario, false, match, false));
        }
        return out;
    }

    private static ScenarioGate gate(GateReport r, String scenario) {
        return r.scenarios().stream().filter(g -> g.scenario().equals(scenario)).findFirst().orElseThrow();
    }

    @Test
    void pass_when_20_conclusive_full_match_no_overestimate() {
        GateReport r = GateEvaluator.evaluate(repeat("SSRF", 20, Boolean.TRUE), NOW);
        ScenarioGate g = gate(r, "SSRF");
        assertEquals(20, g.samples());
        assertEquals(1.0, g.matchRate());
        assertEquals(0, g.overestimateCount());
        assertEquals(GateResult.PASS, g.result());
        assertEquals(GateResult.PASS, r.overall());
    }

    @Test
    void overestimate_forces_fail_even_when_match_rate_meets_threshold() {
        List<VerdictSample> s = repeat("SSRF", 19, Boolean.TRUE);
        s.add(sample("SSRF", false, Boolean.FALSE, true)); // 과대판정 1건 (match=false)
        GateReport r = GateEvaluator.evaluate(s, NOW);
        ScenarioGate g = gate(r, "SSRF");
        assertEquals(20, g.samples());
        assertEquals(0.95, g.matchRate()); // 임계 충족
        assertEquals(1, g.overestimateCount());
        assertEquals(GateResult.FAIL, g.result(), "과대평가 1건이면 일치율 충족해도 FAIL");
    }

    @Test
    void fail_when_match_rate_below_threshold() {
        List<VerdictSample> s = repeat("PATH_TRAVERSAL", 18, Boolean.TRUE);
        s.addAll(repeat("PATH_TRAVERSAL", 2, Boolean.FALSE)); // 불일치 2 (과대평가 아님)
        GateReport r = GateEvaluator.evaluate(s, NOW);
        ScenarioGate g = gate(r, "PATH_TRAVERSAL");
        assertEquals(0.9, g.matchRate());
        assertEquals(0, g.overestimateCount());
        assertEquals(GateResult.FAIL, g.result());
    }

    @Test
    void inconclusive_when_below_min_samples() {
        GateReport r = GateEvaluator.evaluate(repeat("SQLI", 19, Boolean.TRUE), NOW);
        assertEquals(GateResult.INCONCLUSIVE, gate(r, "SQLI").result());
        assertEquals(GateResult.INCONCLUSIVE, r.overall());
    }

    @Test
    void uncertain_excluded_from_denominator_and_tracked_separately() {
        List<VerdictSample> s = repeat("SSRF", 20, Boolean.TRUE);
        for (int i = 0; i < 5; i++) {
            s.add(sample("SSRF", true, null, false)); // UNCERTAIN
        }
        GateReport r = GateEvaluator.evaluate(s, NOW);
        ScenarioGate g = gate(r, "SSRF");
        assertEquals(20, g.samples(), "분모는 conclusive 만");
        assertEquals(1.0, g.matchRate());
        assertEquals(5, g.uncertainCount());
        assertEquals(5.0 / 25.0, g.uncertainRate());
        assertEquals(GateResult.PASS, g.result());
    }

    @Test
    void rolls_up_bf_one_per_op_and_ssrf_per_row() {
        // BF 는 캠페인당 1행(20 op → 20행), SSRF 는 행별(예: 60행). evaluator 는 행을 시나리오별로 센다.
        List<VerdictSample> s = new ArrayList<>();
        s.addAll(repeat("BRUTE_FORCE", 20, Boolean.TRUE));
        s.addAll(repeat("SSRF", 60, Boolean.TRUE));
        GateReport r = GateEvaluator.evaluate(s, NOW);
        assertEquals(20, gate(r, "BRUTE_FORCE").samples());
        assertEquals(60, gate(r, "SSRF").samples());
        assertEquals(80, r.totalSamples());
    }

    @Test
    void overall_is_fail_if_any_scenario_fails() {
        List<VerdictSample> s = new ArrayList<>();
        s.addAll(repeat("SSRF", 20, Boolean.TRUE));             // PASS
        s.addAll(repeat("PATH_TRAVERSAL", 20, Boolean.FALSE));  // FAIL (rate 0)
        GateReport r = GateEvaluator.evaluate(s, NOW);
        assertEquals(GateResult.PASS, gate(r, "SSRF").result());
        assertEquals(GateResult.FAIL, gate(r, "PATH_TRAVERSAL").result());
        assertEquals(GateResult.FAIL, r.overall());
    }

    @Test
    void empty_samples_is_inconclusive() {
        assertEquals(GateResult.INCONCLUSIVE, GateEvaluator.evaluate(List.of(), NOW).overall());
    }
}
