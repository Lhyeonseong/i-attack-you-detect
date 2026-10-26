package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CorrelationEngine → VerdictEngine 관통 테스트 (BF 탐지 기준 · 스프레이 캠페인 접기)
 * 탐지 상태는 alert(ruleId·srcIp·username)만으로 판정하고, 정답지는 결정표에서만 쓴다 (B안).
 */
class DetectionAndSprayTest {

    private static final Instant T0 = Instant.parse("2026-10-13T00:00:00Z");
    private static final String IP = "172.20.0.1";
    private static final long ALERT_DELAY_MS = 700;

    private final List<AttackEvent> events = new ArrayList<>();
    private final List<AlertEvent> alerts = new ArrayList<>();

    /** 로그인 시도 1건 + (alertRule 이 있으면) 그 요청에 대한 Wazuh alert 1건 */
    private void login(String rid, String username, long offsetMs, GroundTruthOutcome gt, String alertRule) {
        events.add(new AttackEvent(new CorrelationKey("paw-1", "7aa89a87", rid), "BRUTE_FORCE", "T1110",
                T0.plusMillis(offsetMs), IP, "/api/auth/login", username, gt));
        if (alertRule != null) {
            alerts.add(new AlertEvent(alertRule, "T1110", T0.plusMillis(offsetMs + ALERT_DELAY_MS), null,
                    rid, "paw-1", "7aa89a87", IP, "/api/auth/login", CorrelationSource.HEADER, username));
        }
    }

    private List<VerdictResult> run(int sprayThreshold) {
        List<Correlation> correlations = new CorrelationEngine(null, sprayThreshold).correlate(events, alerts);
        return new VerdictEngine(sprayThreshold).judge(correlations);
    }

    private List<VerdictResult> run() {
        return run(CorrelationEngine.DEFAULT_SPRAY_ACCOUNT_THRESHOLD);
    }

    private static VerdictResult only(List<VerdictResult> results) {
        assertEquals(1, results.size());
        return results.get(0);
    }

    // ---- B: BF 계정 집중형 (AN1275 / AN1276) ----

    /** Gap#1 이 Verdict 까지 관통: 240ms 버스트 실패 alert 10개 + 성공 alert → alert time 기준으로 탐지 */
    @Test
    void b1BurstOfTenFailureAlertsPlusSuccessAlertIsDetectedWithCompromise() {
        for (int i = 0; i < 10; i++) {
            login("f" + i, "admin", i * 24L, GroundTruthOutcome.FAILED, "100230");
        }
        login("s", "admin", 240, GroundTruthOutcome.SUCCEEDED, "100232");

        VerdictResult r = only(run());

        assertEquals(UnitType.BF_SEQUENCE, r.unitType());
        assertEquals(DetectionStatus.DETECTED, r.detectionStatus());
        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
        assertEquals(9 * 24L + ALERT_DELAY_MS, r.mttdMs());
        assertEquals(Boolean.TRUE, r.compromiseDetected());
        assertEquals(T0.plusMillis(240 + ALERT_DELAY_MS), r.compromiseAlertTime());
        assertFalse(r.lateDetection());
    }

    @Test
    void b2OnlyThreeFailureAlertsIsNotDetectedEvenWithLinks() {
        for (int i = 0; i < 10; i++) {
            login("f" + i, "admin", i * 24L, GroundTruthOutcome.FAILED, i < 3 ? "100230" : null);
        }
        login("s", "admin", 240, GroundTruthOutcome.SUCCEEDED, null);

        VerdictResult r = only(run());

        assertEquals(1.0, r.bestConfidence());
        assertEquals(DetectionStatus.NOT_DETECTED, r.detectionStatus());
        assertEquals(Verdict.SUCCEEDED_MISSED, r.verdict());
        assertNull(r.mttdMs());
    }

    /** 탐지 상태는 정답지와 무관: 성공 alert 가 없어도 실패 alert 10개면 DETECTED, 침해 탐지는 false */
    @Test
    void b3TenFailureAlertsWithoutSuccessAlertIsDetectedWithoutCompromise() {
        for (int i = 0; i < 10; i++) {
            login("f" + i, "admin", i * 24L, GroundTruthOutcome.FAILED, "100230");
        }
        login("s", "admin", 240, GroundTruthOutcome.SUCCEEDED, null);

        VerdictResult r = only(run());

        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
        assertEquals(Boolean.FALSE, r.compromiseDetected());
        assertNull(r.compromiseAlertTime());
    }

    /**
     * T6 (ADR-S4-01 v1.7 R16): Wazuh 는 같은 이벤트에서 하위 룰 100233 을 우선해 100232 를 내지 않는다
     * (실측 S4-STACK-6-BASELINE 100232 = 0, 100233 = 20). 100233 만 있어도 compromise 로 본다.
     */
    @Test
    void b5CompromiseRuleAloneMarksCompromiseDetected() {
        for (int i = 0; i < 10; i++) {
            login("f" + i, "admin", i * 24L, GroundTruthOutcome.FAILED, "100230");
        }
        login("s", "admin", 240, GroundTruthOutcome.SUCCEEDED, "100233");

        VerdictResult r = only(run());

        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
        assertEquals(9 * 24L + ALERT_DELAY_MS, r.mttdMs());
        assertEquals(Boolean.TRUE, r.compromiseDetected());
        assertEquals(T0.plusMillis(240 + ALERT_DELAY_MS), r.compromiseAlertTime());
    }

    /** username 없는 alert(예: Suricata)는 계정 집계에서 제외 — rid 로 붙은 Correlation 의 username 을 빌려 쓰지 않는다 */
    @Test
    void b4FailureAlertsWithoutUsernameAreNotCounted() {
        for (int i = 0; i < 10; i++) {
            login("f" + i, "admin", i * 24L, GroundTruthOutcome.FAILED, null);
            alerts.add(new AlertEvent("100230", "T1110", T0.plusMillis(i * 24L + ALERT_DELAY_MS), null,
                    "f" + i, "paw-1", "7aa89a87", IP, "/api/auth/login", CorrelationSource.HEADER));
        }

        VerdictResult r = only(run());

        assertEquals(DetectionStatus.NOT_DETECTED, r.detectionStatus());
        assertEquals(Verdict.FAILED_UNSEEN, r.verdict());
    }

    @Test
    void usernameIsParsedFromRequestArgs() {
        assertEquals("admin", AlertEvent.usernameFromArgs("username=admin"));
        assertEquals("bob", AlertEvent.usernameFromArgs("x=1&username=bob"));
        assertNull(AlertEvent.usernameFromArgs("url=http://169.254.169.254/latest"));
        assertNull(AlertEvent.usernameFromArgs("username="));
        assertNull(AlertEvent.usernameFromArgs(null));
    }

    // ---- S: 스프레이 (AN1277) — IP 캠페인 1건 = Verdict 1개 ----

    private void spray(int accounts, int successAccount) {
        for (int u = 0; u < accounts; u++) {
            for (int i = 0; i < 2; i++) {
                login("u" + u + "-" + i, "user" + u, u * 100L + i * 10, GroundTruthOutcome.FAILED, "100230");
            }
            if (u == successAccount) {
                login("u" + u + "-s", "user" + u, u * 100L + 50, GroundTruthOutcome.SUCCEEDED, "100232");
            }
        }
    }

    @Test
    void s1SixAccountSprayFoldsIntoOneCampaignVerdict() {
        spray(6, -1);

        VerdictResult r = only(run());

        assertEquals(UnitType.SPRAY_CAMPAIGN, r.unitType());
        assertEquals(6, r.sprayAccountCount());
        assertEquals(6, r.memberCorrelationIds().size());
        assertEquals(DetectionStatus.DETECTED, r.detectionStatus());
        assertEquals(GroundTruthOutcome.FAILED, r.gtOutcome());
        assertEquals(Verdict.FAILED_DETECTED, r.verdict());
    }

    @Test
    void s2OneCompromisedAccountMakesCampaignSucceeded() {
        spray(6, 3);

        VerdictResult r = only(run());

        assertEquals(GroundTruthOutcome.SUCCEEDED, r.gtOutcome());
        assertEquals(Verdict.SUCCEEDED_DETECTED, r.verdict());
    }

    @Test
    void s3FourAccountsBelowThresholdStayIndividualVerdicts() {
        spray(4, -1);

        List<VerdictResult> results = run();

        assertEquals(4, results.size());
        for (VerdictResult r : results) {
            assertEquals(UnitType.BF_SEQUENCE, r.unitType());
            assertEquals(1, r.memberCorrelationIds().size());
        }
    }

    @Test
    void s4ConfiguredThresholdThreeFoldsThreeAccounts() {
        spray(3, -1);

        VerdictResult r = only(run(3));

        assertEquals(UnitType.SPRAY_CAMPAIGN, r.unitType());
        assertEquals(3, r.sprayAccountCount());
        assertEquals(DetectionStatus.DETECTED, r.detectionStatus());
    }
}
