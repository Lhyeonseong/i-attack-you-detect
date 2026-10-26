package com.capstone.vuln.measure;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 게이트 판정(순수 함수). verdict_result 표본을 시나리오별로 롤업하고 임계와 비교만 한다 —
 * match/overestimate 를 새로 계산하지 않는다.
 *
 * <p>집계 단위 = VerdictSample 1건(= verdict_result 1행). BF 는 judge 가 캠페인당 1행(BF_SEQUENCE)으로
 * 내므로 자연히 1표본, SSRF/PT 는 행별 N표본. matchRate 분모 = conclusive(UNCERTAIN 제외).
 *
 * <p>임계: conclusive 표본 ≥ {@value #MIN_CONCLUSIVE_SAMPLES} & matchRate ≥ {@value #MIN_MATCH_RATE}
 * & overestimate == 0 → PASS / 표본 < 20 → INCONCLUSIVE / 그 외 → FAIL.
 */
public final class GateEvaluator {

    public static final int MIN_CONCLUSIVE_SAMPLES = 20;
    public static final double MIN_MATCH_RATE = 0.95;

    private GateEvaluator() {
    }

    public static GateReport evaluate(List<VerdictSample> samples, Instant generatedAt) {
        Map<String, List<VerdictSample>> byScenario = new TreeMap<>();
        for (VerdictSample s : samples) {
            String scenario = s.scenario() == null ? "UNKNOWN" : s.scenario();
            byScenario.computeIfAbsent(scenario, k -> new ArrayList<>()).add(s);
        }

        List<ScenarioGate> gates = new ArrayList<>();
        int totalConclusive = 0;
        int totalUncertain = 0;
        for (Map.Entry<String, List<VerdictSample>> e : byScenario.entrySet()) {
            List<VerdictSample> all = e.getValue();
            int uncertain = (int) all.stream().filter(VerdictSample::uncertain).count();
            List<VerdictSample> conclusive = all.stream().filter(s -> !s.uncertain()).toList();
            int n = conclusive.size();
            long matched = conclusive.stream().filter(s -> Boolean.TRUE.equals(s.attackerMatch())).count();
            int overestimate = (int) all.stream().filter(VerdictSample::overestimate).count();
            double matchRate = n == 0 ? 0.0 : (double) matched / n;
            double uncertainRate = all.isEmpty() ? 0.0 : (double) uncertain / all.size();

            GateResult result;
            if (n < MIN_CONCLUSIVE_SAMPLES) {
                result = GateResult.INCONCLUSIVE;
            } else if (matchRate >= MIN_MATCH_RATE && overestimate == 0) {
                result = GateResult.PASS;
            } else {
                result = GateResult.FAIL;
            }
            gates.add(new ScenarioGate(e.getKey(), n, matchRate, overestimate, uncertain, uncertainRate, result));
            totalConclusive += n;
            totalUncertain += uncertain;
        }

        GateResult overall;
        if (gates.isEmpty()) {
            overall = GateResult.INCONCLUSIVE;
        } else if (gates.stream().anyMatch(g -> g.result() == GateResult.FAIL)) {
            overall = GateResult.FAIL;
        } else if (gates.stream().anyMatch(g -> g.result() == GateResult.INCONCLUSIVE)) {
            overall = GateResult.INCONCLUSIVE;
        } else {
            overall = GateResult.PASS;
        }
        return new GateReport(generatedAt, totalConclusive, totalUncertain, gates, overall);
    }
}
