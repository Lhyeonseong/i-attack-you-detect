package com.capstone.vuln.measure;

import java.util.List;

/** op 1회 측정의 per-run 요약 — 저장된 VerdictResult 들을 행 단위로 담는다. */
public record PerRunSummary(String opId, List<ScenarioResult> results) {
}
