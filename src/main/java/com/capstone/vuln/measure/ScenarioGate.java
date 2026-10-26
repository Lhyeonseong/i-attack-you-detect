package com.capstone.vuln.measure;

/**
 * 시나리오 1개의 게이트 집계·판정.
 * - samples: conclusive 표본수(UNCERTAIN 제외). 분모.
 * - matchRate: match=true / conclusive.
 * - overestimateCount: 과대판정 건수(0이어야 PASS).
 * - uncertainCount/uncertainRate: 가드레일(분모 밖 별도).
 */
public record ScenarioGate(String scenario,
                           int samples,
                           double matchRate,
                           int overestimateCount,
                           int uncertainCount,
                           double uncertainRate,
                           GateResult result) {
}
