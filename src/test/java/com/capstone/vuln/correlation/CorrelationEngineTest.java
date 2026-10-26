package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationEngineTest {

    private static final Instant T0 = Instant.parse("2026-10-13T00:00:00Z");
    private static final String IP = "172.20.0.1";

    private final CorrelationEngine engine = new CorrelationEngine();

    private static AttackEvent attack(String rid, String op, String ability, String scenario, String technique,
                                      String endpoint, long offsetMs, GroundTruthOutcome gt) {
        return new AttackEvent(new CorrelationKey(op, ability, rid), scenario, technique,
                T0.plusMillis(offsetMs), IP, endpoint, null, gt);
    }

    private static AttackEvent login(String rid, String paw, String username, long offsetMs, GroundTruthOutcome gt) {
        return new AttackEvent(new CorrelationKey(paw, "7aa89a87", rid), "BRUTE_FORCE", "T1110",
                T0.plusMillis(offsetMs), IP, "/api/auth/login", username, gt);
    }

    private static Correlation byUser(List<Correlation> result, String username) {
        return result.stream().filter(c -> username.equals(c.getUsername())).findFirst().orElseThrow();
    }

    private static AttackEvent ssrf(String rid, String op, String ability) {
        return attack(rid, op, ability, "SSRF", "T1190", "/api/preview", 0, GroundTruthOutcome.SUCCEEDED);
    }

    private static AlertEvent alert(String rid, String op, String ability, CorrelationSource idSource,
                                    long offsetMs, Instant searchableTime) {
        return new AlertEvent("100240", "T1190", T0.plusMillis(offsetMs), searchableTime,
                rid, op, ability, IP, "/api/preview", idSource);
    }

    /**
     * Gap#1 재현 (known-gaps.md): 실패 10회를 240ms 안에(24ms 간격) 몰아넣은 뒤 성공 1회.
     * Wazuh 는 analysisd 병렬 매칭 때문에 100231(실패 반복)·100233(실패 후 성공)을 놓쳤지만,
     * Backend 엔진은 처리 순서가 아니라 이벤트 time 기준으로 세므로 시퀀스를 잡는다.
     * 입력 순서를 뒤섞어 도착 순서와 무관함도 확인한다.
     */
    @Test
    void bruteForceBurstIsGroupedAndSequenceIsEstablishedByEventTime() {
        String op = "djlycn";
        String ability = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";
        List<AttackEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(attack("rid-f" + i, op, ability, "BRUTE_FORCE", "T1110", "/api/auth/login",
                    i * 24L, GroundTruthOutcome.FAILED));
        }
        events.add(attack("rid-s", op, ability, "BRUTE_FORCE", "T1110", "/api/auth/login",
                240, GroundTruthOutcome.SUCCEEDED));
        Collections.reverse(events);

        List<Correlation> result = engine.correlate(events, List.of());

        assertEquals(1, result.size());
        Correlation c = result.get(0);
        assertEquals(11, c.getEventCount());
        assertEquals(10, c.getBfFailureCount());
        assertTrue(c.isBfSequence());
        assertEquals(GroundTruthOutcome.SUCCEEDED, c.getGtOutcome());
        assertEquals(T0, c.getAttackTime());
        assertEquals(T0.plusMillis(240).plusSeconds(30), c.getObservedUntil());
    }

    @Test
    void headerMatchedAlertWithinWindowIsDetectedWithMttd() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert(null, "op-1", "ab-1", CorrelationSource.HEADER, 700, null)));

        Correlation c = result.get(0);
        assertEquals(DetectionStatus.DETECTED, c.getDetectionStatus());
        assertEquals(0.9, c.getBestConfidence());
        assertEquals(MatchSource.HEADER, c.getCorrelationSource());
        assertEquals(700L, c.getMttdMs());
    }

    @Test
    void attackWithoutMatchingAlertIsNotDetected() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert("rid-other", "op-2", "ab-2", CorrelationSource.HEADER, 500, null)));

        Correlation c = result.get(0);
        assertEquals(DetectionStatus.NOT_DETECTED, c.getDetectionStatus());
        assertNull(c.getMttdMs());
        assertTrue(c.getLinks().isEmpty());
    }

    @Test
    void alertArrivingAfterWindowIsLateAndNotDetected() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert("rid-1", "op-1", "ab-1", CorrelationSource.HEADER, 31_000, null)));

        Correlation c = result.get(0);
        assertTrue(c.isLateDetection());
        assertEquals(1, c.getLinks().size());
        assertEquals(DetectionStatus.NOT_DETECTED, c.getDetectionStatus());
        assertNull(c.getMttdMs());
    }

    @Test
    void sameEndpointIpAndWindowOnlyIsTimeOnlyAndNotUsable() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert(null, null, null, CorrelationSource.NONE, 900, null)));

        Correlation c = result.get(0);
        assertEquals(1, c.getLinks().size());
        assertEquals(MatchPath.TIME_ONLY, c.getLinks().get(0).matchPath());
        assertEquals(0.3, c.getBestConfidence());
        assertEquals(MatchSource.NONE, c.getCorrelationSource());
        assertEquals(DetectionStatus.NOT_DETECTED, c.getDetectionStatus());
        assertFalse(c.isLateDetection());
    }

    @Test
    void ingestionLagIsAlertTimeToSearchableTime() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert("rid-1", "op-1", "ab-1", CorrelationSource.HEADER, 688,
                        T0.plusMillis(688 + 10_221))));

        Correlation c = result.get(0);
        assertEquals(MatchSource.RID, c.getCorrelationSource());
        assertEquals(688L, c.getMttdMs());
        assertEquals(10_221L, c.getIngestionLagMs());
    }

    // ---- S3-3 B-1: BF 그룹 = srcIp 1차 + username 하위 (op/ability 는 라벨) ----

    /**
     * 같은 IP 에서 계정 2개를 각각 집중 공격(AN1275 계정 반복 + AN1276 실패 후 성공) → 계정별로 따로 성립.
     * IP 만으로 뭉개지 않는다. alice 는 중간에 op(paw)가 바뀌어도 한 시퀀스(op 는 그룹 키가 아님) —
     * 대표 op 는 성공 이벤트의 것.
     */
    @Test
    void sameIpTwoAccountsEachFormOwnSequenceRegardlessOfOpChange() {
        List<AttackEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(login("a-f" + i, i < 5 ? "paw-1" : "paw-2", "alice", i * 24L, GroundTruthOutcome.FAILED));
            events.add(login("b-f" + i, "paw-1", "bob", i * 24L + 7, GroundTruthOutcome.FAILED));
        }
        events.add(login("a-s", "paw-2", "alice", 300, GroundTruthOutcome.SUCCEEDED));
        events.add(login("b-s", "paw-1", "bob", 310, GroundTruthOutcome.SUCCEEDED));

        List<Correlation> result = engine.correlate(events, List.of());

        assertEquals(2, result.size());
        Correlation alice = byUser(result, "alice");
        assertTrue(alice.isBfSequence());
        assertEquals(10, alice.getBfFailureCount());
        assertEquals("paw-2", alice.getKey().agentPaw());
        Correlation bob = byUser(result, "bob");
        assertTrue(bob.isBfSequence());
        assertEquals(10, bob.getBfFailureCount());
        assertFalse(alice.isSpray());
    }

    /** 스프레이(AN1277): 같은 IP 가 계정 5개에 각 2회씩 → 계정별 시퀀스는 불성립, spray=true·계정수 5 */
    @Test
    void sameIpFewAttemptsAcrossFiveAccountsIsSpray() {
        List<AttackEvent> events = new ArrayList<>();
        for (int u = 0; u < 5; u++) {
            for (int i = 0; i < 2; i++) {
                events.add(login("u" + u + "-" + i, "paw-1", "user" + u, u * 100L + i * 10, GroundTruthOutcome.FAILED));
            }
        }

        List<Correlation> result = engine.correlate(events, List.of());

        assertEquals(5, result.size());
        for (Correlation c : result) {
            assertTrue(c.isSpray());
            assertEquals(5, c.getSprayAccountCount());
            assertFalse(c.isBfSequence());
        }
    }

    // ---- S3-3 B-2: 마지막 실패 후 120s 넘는 공백이면 새 Correlation (Sigma temporal timespan) ----

    @Test
    void gapOverTimeframeAfterLastFailureSplitsIntoTwoCorrelations() {
        List<AttackEvent> events = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            events.add(login("f1-" + i, "paw-1", "admin", i * 1_000L, GroundTruthOutcome.FAILED));
        }
        long resume = 4_000 + 200_000;
        for (int i = 0; i < 5; i++) {
            events.add(login("f2-" + i, "paw-1", "admin", resume + i * 1_000L, GroundTruthOutcome.FAILED));
        }
        events.add(login("s", "paw-1", "admin", resume + 5_000, GroundTruthOutcome.SUCCEEDED));

        List<Correlation> result = engine.correlate(events, List.of());

        assertEquals(2, result.size());
        Correlation before = result.get(0);
        assertEquals(5, before.getEventCount());
        assertEquals(GroundTruthOutcome.FAILED, before.getGtOutcome());
        Correlation after = result.get(1);
        assertEquals(6, after.getEventCount());
        assertEquals(T0.plusMillis(resume), after.getAttackTime());
        assertEquals(GroundTruthOutcome.SUCCEEDED, after.getGtOutcome());
        assertFalse(after.isBfSequence());
    }

    // ---- S3-3 B-3: 늦은 alert 상한 (설정값, 기본 비활성) ----

    @Test
    void byDefaultVeryLateAlertIsStillLinkedAsLate() {
        List<Correlation> result = engine.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert("rid-1", "op-1", "ab-1", CorrelationSource.HEADER, 3_600_000, null)));

        Correlation c = result.get(0);
        assertEquals(1, c.getLinks().size());
        assertTrue(c.isLateDetection());
        assertEquals(DetectionStatus.NOT_DETECTED, c.getDetectionStatus());
    }

    @Test
    void alertBeyondConfiguredLateCapIsNotLinked() {
        CorrelationEngine capped = new CorrelationEngine(Duration.ofSeconds(60));

        List<Correlation> result = capped.correlate(
                List.of(ssrf("rid-1", "op-1", "ab-1")),
                List.of(alert("rid-1", "op-1", "ab-1", CorrelationSource.HEADER, 30_000 + 61_000, null)));

        Correlation c = result.get(0);
        assertTrue(c.getLinks().isEmpty());
        assertFalse(c.isLateDetection());
    }
}
