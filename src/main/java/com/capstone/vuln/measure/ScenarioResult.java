package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.DetectionStatus;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.UnitType;
import com.capstone.vuln.correlation.Verdict;

/**
 * per-run 요약 1행 (= VerdictResult 1건 = judge Unit 1개). 값은 전부 엔진 출력 그대로 담는다
 * (match/overestimate/verdict/confidence 를 harness 가 새로 계산하지 않는다).
 *
 * - unitKind: SINGLE / BF_SEQUENCE / SPRAY_CAMPAIGN — b-3 게이트가 표본 단위(SSRF rid별 N vs
 *   BF 캠페인 1)를 올바로 롤업하기 위한 노출값.
 * - rid: 대표 rid(VerdictResult.memberCorrelationIds().get(0)).
 * - attackerMatch: gt=UNKNOWN 또는 attacker 없음이면 null(플래그).
 * - overestimate: attacker=SUCCEEDED & gt=FAILED (과대판정).
 */
public record ScenarioResult(String scenario,
                             UnitType unitKind,
                             String opId,
                             String rid,
                             GroundTruthOutcome gtOutcome,
                             GroundTruthOutcome attackerVerdict,
                             Boolean attackerMatch,
                             boolean overestimate,
                             Verdict verdict,
                             double bestConfidence,
                             DetectionStatus detectionStatus,
                             Long mttdMs) {
}
