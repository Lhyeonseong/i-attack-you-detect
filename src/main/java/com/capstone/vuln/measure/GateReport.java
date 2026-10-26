package com.capstone.vuln.measure;

import java.time.Instant;
import java.util.List;

/**
 * 전체 게이트 리포트. overall = 하나라도 FAIL → FAIL / 아니면 하나라도 INCONCLUSIVE → INCONCLUSIVE /
 * 전부 PASS → PASS (표본 없으면 INCONCLUSIVE).
 */
public record GateReport(Instant generatedAt,
                         int totalSamples,
                         int totalUncertain,
                         List<ScenarioGate> scenarios,
                         GateResult overall) {
}
