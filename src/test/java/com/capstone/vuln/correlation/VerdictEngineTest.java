package com.capstone.vuln.correlation;

import com.capstone.vuln.attack.AttackOutcome;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerdictEngineTest {

    private static final Instant T0 = Instant.parse("2026-10-13T00:00:00Z");
    private static final String IP = "172.20.0.1";

    private final VerdictEngine engine = new VerdictEngine();

    private static Correlation ssrf(GroundTruthOutcome gt, AttackOutcome attacker) {
        Correlation c = new Correlation(new CorrelationKey("paw-1", "a7f3c1d9", "rid-1"),
                "SSRF", "T1190", T0, IP);
        c.setGtOutcome(gt);
        c.setAttackerVerdict(attacker);
        return c;
    }

    private static DetectionLink ssrfAlert(long offsetMs, MatchPath path) {
        return DetectionLink.of("100240", "T1190", T0.plusMillis(offsetMs), path);
    }

    private VerdictResult judgeOne(Correlation c) {
        List<VerdictResult> results = engine.judge(List.of(c));
        assertEquals(1, results.size());
        return results.get(0);
    }

    // ---- V: 7상태 결정표 ----

    @Test
    void v1SucceededWithoutAlertIsMissed() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.SUCCEEDED, AttackOutcome.SUCCEEDED));

        assertEquals(Verdict.SUCCEEDED_MISSED, r.verdict());
        assertEquals(DetectionStatus.NOT_DETECTED, r.detectionStatus());
        assertEquals(UnitType.SINGLE, r.unitType());
        assertNull(r.mttdMs());
        assertNull(r.uncertainReason());
    }

    @Test
    void v2SucceededWithTechniqueAlertIsDetected() {
        Correlation c = ssrf(GroundTruthOutcome.SUCCEEDED, AttackOutcome.SUCCEEDED);
        c.addLink(ssrfAlert(700, MatchPath.HEADER));

        VerdictResult r = judgeOne(c);

        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
        assertEquals(DetectionStatus.DETECTED, r.detectionStatus());
        assertEquals(700L, r.mttdMs());
        assertEquals(0.9, r.bestConfidence());
        assertEquals(List.of("rid-1"), r.memberCorrelationIds());
    }

    @Test
    void v3FailedWithAlertIsFailedDetected() {
        Correlation c = ssrf(GroundTruthOutcome.FAILED, AttackOutcome.FAILED);
        c.addLink(ssrfAlert(500, MatchPath.RID));

        assertEquals(Verdict.FAILED_DETECTED, judgeOne(c).verdict());
    }

    @Test
    void v4FailedWithoutAlertIsFailedUnseen() {
        assertEquals(Verdict.FAILED_UNSEEN,
                judgeOne(ssrf(GroundTruthOutcome.FAILED, AttackOutcome.FAILED)).verdict());
    }

    @Test
    void v5FailedAndBlockedIsBlocked() {
        VerdictEngine.Decision d = VerdictEngine.decide(GroundTruthOutcome.FAILED, true,
                DetectionStatus.BLOCKED, true, 1.0);

        assertEquals(Verdict.BLOCKED, d.verdict());
        assertNull(d.reason());
    }

    @Test
    void v6SucceededAndBlockedIsSucceededBlocked() {
        VerdictEngine.Decision d = VerdictEngine.decide(GroundTruthOutcome.SUCCEEDED, true,
                DetectionStatus.BLOCKED, true, 1.0);

        assertEquals(Verdict.SUCCEEDED_BLOCKED, d.verdict());
    }

    // ---- U: UNCERTAIN 3트리거 ----

    @Test
    void u1UnknownGroundTruthWithAttackerFactIsGtUnknown() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.UNKNOWN, AttackOutcome.FAILED));

        assertEquals(Verdict.UNCERTAIN, r.verdict());
        assertEquals(UncertainReason.GT_UNKNOWN, r.uncertainReason());
    }

    @Test
    void u2OnlyTimeOnlyLinkIsLowConfidence() {
        Correlation c = ssrf(GroundTruthOutcome.SUCCEEDED, AttackOutcome.SUCCEEDED);
        c.addLink(ssrfAlert(900, MatchPath.TIME_ONLY));

        VerdictResult r = judgeOne(c);

        assertEquals(Verdict.UNCERTAIN, r.verdict());
        assertEquals(UncertainReason.LOW_CONFIDENCE, r.uncertainReason());
        assertEquals(DetectionStatus.NOT_DETECTED, r.detectionStatus());
    }

    @Test
    void u3UnknownGroundTruthWithoutAttackerFactIsNoEvidence() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.UNKNOWN, null));

        assertEquals(Verdict.UNCERTAIN, r.verdict());
        assertEquals(UncertainReason.NO_EVIDENCE, r.uncertainReason());
    }

    // ---- E: EXECUTED → UNKNOWN (결정2: 간접신호 단독은 성공 아님) ----

    @Test
    void e1ExecutedValidationMapsToUnknownAndUncertain() {
        assertEquals(GroundTruthOutcome.SUCCEEDED, GroundTruthOutcome.fromValidation("SUCCEEDED"));
        assertEquals(GroundTruthOutcome.FAILED, GroundTruthOutcome.fromValidation("FAILED"));
        assertEquals(GroundTruthOutcome.UNKNOWN, GroundTruthOutcome.fromValidation("EXECUTED"));
        assertEquals(GroundTruthOutcome.UNKNOWN, GroundTruthOutcome.fromValidation("UNKNOWN"));
        assertEquals(GroundTruthOutcome.UNKNOWN, GroundTruthOutcome.fromValidation(null));
        assertEquals(GroundTruthOutcome.UNKNOWN, GroundTruthOutcome.fromValidation("garbage"));

        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.fromValidation("EXECUTED"), AttackOutcome.EXECUTED));

        assertEquals(Verdict.UNCERTAIN, r.verdict());
        assertEquals(UncertainReason.GT_UNKNOWN, r.uncertainReason());
    }

    // ---- A: 공격자 측 판정 정확도 (Verdict 엔 영향 없음) ----

    @Test
    void a1AttackerAgreesWithGroundTruth() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.SUCCEEDED, AttackOutcome.SUCCEEDED));

        assertEquals(Boolean.TRUE, r.attackerMatch());
        assertFalse(r.overestimate());
    }

    @Test
    void a2AttackerSucceededButGroundTruthFailedIsOverestimate() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.FAILED, AttackOutcome.SUCCEEDED));

        assertEquals(Boolean.FALSE, r.attackerMatch());
        assertTrue(r.overestimate());
        assertEquals(Verdict.FAILED_UNSEEN, r.verdict());
    }

    @Test
    void a3MissingAttackerFactIsExcludedFromAccuracy() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.SUCCEEDED, null));

        assertNull(r.attackerMatch());
        assertNull(r.attackerVerdict());
        assertFalse(r.overestimate());
    }

    @Test
    void a4AttackerExecutedAgainstSucceededIsMismatch() {
        VerdictResult r = judgeOne(ssrf(GroundTruthOutcome.SUCCEEDED, AttackOutcome.EXECUTED));

        assertEquals(GroundTruthOutcome.UNKNOWN, r.attackerVerdict());
        assertEquals(Boolean.FALSE, r.attackerMatch());
    }

    // ---- L: 늦은 alert 로 기준 충족 → 결정4 (Verdict 수정 + 이력) ----

    @Test
    void l1CriterionMetOnlyByLateAlertUpgradesVerdictWithHistory() {
        Correlation c = new Correlation(new CorrelationKey("paw-1", "7aa89a87", "rid-1"),
                "BRUTE_FORCE", "T1110", T0, IP);
        c.setUsername("admin");
        c.setGtOutcome(GroundTruthOutcome.SUCCEEDED);
        for (int i = 1; i <= 9; i++) {
            c.addLink(new DetectionLink("100230", "T1110", T0.plusSeconds(i), MatchPath.RID, 1.0, IP, "admin"));
        }
        Instant late = T0.plusSeconds(40);
        c.addLink(new DetectionLink("100230", "T1110", late, MatchPath.RID, 1.0, IP, "admin"));

        VerdictResult r = judgeOne(c);

        assertEquals(UnitType.BF_SEQUENCE, r.unitType());
        assertEquals(Verdict.SUCCEEDED_MISSED, r.initialVerdict());
        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
        assertTrue(r.lateDetection());
        assertEquals(40_000L, r.mttdMs());
    }
}
