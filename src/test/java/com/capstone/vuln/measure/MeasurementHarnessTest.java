package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.AttemptRole;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.UnitType;
import com.capstone.vuln.correlation.Verdict;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * harness 단위테스트 — correlate/judge 는 실제 엔진 호출, collect 는 고정 CollectedWindow 주입,
 * save 는 리포지토리 모킹(실 DB 없음). match/overestimate/verdict 는 엔진 산출값을 그대로 검증.
 */
class MeasurementHarnessTest {

    private static final long BASE = 1_000_000_000_000L;
    private static final String PAW = "mcukpa";
    private static final UUID RUN_ID = UUID.fromString("00000000-0000-0000-0000-0000000000b2");

    private static final Instant ATTACK_TIME = Instant.ofEpochMilli(BASE);
    private static final Instant OP_FINISH = Instant.ofEpochMilli(BASE + 60_000);

    /** collect 가 고정 window 를 돌려주도록 하는 가짜 수집기(리더 미사용). */
    private static final class FixedCollector extends MeasurementCollector {
        private final CollectedWindow window;

        FixedCollector(CollectedWindow window) {
            super(null, null, null, Duration.ZERO);
            this.window = window;
        }

        @Override
        public CollectedWindow collect(String opId, Instant attackTime, Instant opFinish) {
            return window;
        }
    }

    private static AttackEvent attack(String rid, String ability, String scenario, String tech,
                                      long ms, GroundTruthOutcome gt, String user) {
        return new AttackEvent(new CorrelationKey(PAW, ability, rid), scenario, tech,
                Instant.ofEpochMilli(BASE + ms), "1.2.3.4", "/x", user, gt);
    }

    private static PerRunSummary run(CollectedWindow window, VerdictRepository repo) {
        MeasurementHarness harness = new MeasurementHarness(
                new FixedCollector(window), new CorrelationEngine(), new VerdictEngine(), repo,
                new OperationResolver(List::of)); // 링크 없음 → 기존 테스트는 op 미해석 그대로
        return harness.measure(RUN_ID, "op-1", ATTACK_TIME, OP_FINISH);
    }

    @Test
    void ssrf_mixed_outcomes_yield_match_and_overestimate_rows() {
        List<AttackEvent> attacks = List.of(
                attack("s1", "ab-ssrf", "SSRF", "T1190", 1_000, GroundTruthOutcome.SUCCEEDED, null),
                attack("s2", "ab-ssrf", "SSRF", "T1190", 2_000, GroundTruthOutcome.SUCCEEDED, null),
                attack("f1", "ab-ssrf", "SSRF", "T1190", 3_000, GroundTruthOutcome.FAILED, null));
        CollectedWindow window = new CollectedWindow(attacks, List.of(),
                Map.of(new PawAbility(PAW, "ab-ssrf"), AttackOutcome.SUCCEEDED),
                Map.of("f1", AttemptRole.CONTROL));

        VerdictRepository repo = mock(VerdictRepository.class);
        PerRunSummary summary = run(window, repo);

        assertEquals(3, summary.results().size()); // SSRF 는 rid별 (접히지 않음)
        // CONTROL 은 ability 공통 attacker verdict 를 상속하지 않는다.
        ScenarioResult control = summary.results().stream()
                .filter(r -> r.gtOutcome() == GroundTruthOutcome.FAILED).findFirst().orElseThrow();
        assertFalse(control.overestimate());
        assertNull(control.attackerMatch());
        assertNull(control.attackerVerdict());
        // gt=SUCCEEDED 2건: match=true, overestimate=false
        assertEquals(2, summary.results().stream()
                .filter(r -> r.gtOutcome() == GroundTruthOutcome.SUCCEEDED
                        && Boolean.TRUE.equals(r.attackerMatch()) && !r.overestimate()).count());
        summary.results().forEach(r -> assertEquals(UnitType.SINGLE, r.unitKind()));
        verify(repo, times(1)).save(eq(RUN_ID), anyList(), anyList(), anyMap());
    }

    @Test
    void brute_force_collapses_to_one_bf_sequence_row_with_attacker_verdict() {
        java.util.List<AttackEvent> attacks = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            attacks.add(attack("bf-f" + i, "7aa89a87", "BRUTE_FORCE", "T1110",
                    i * 1_000L, GroundTruthOutcome.FAILED, "user1"));
        }
        attacks.add(attack("bf-s", "7aa89a87", "BRUTE_FORCE", "T1110",
                12_000L, GroundTruthOutcome.SUCCEEDED, "user1"));
        CollectedWindow window = new CollectedWindow(attacks, List.of(),
                Map.of(new PawAbility(PAW, "7aa89a87"), AttackOutcome.SUCCEEDED));

        PerRunSummary summary = run(window, mock(VerdictRepository.class));

        assertEquals(1, summary.results().size()); // 13 이벤트 → 1건으로 접힘
        ScenarioResult bf = summary.results().get(0);
        assertEquals(UnitType.BF_SEQUENCE, bf.unitKind());
        assertEquals("BRUTE_FORCE", bf.scenario());
        assertEquals(GroundTruthOutcome.SUCCEEDED, bf.attackerVerdict()); // (mcukpa,7aa89a87) 부착
        assertEquals(GroundTruthOutcome.SUCCEEDED, bf.gtOutcome());
        assertEquals(Boolean.TRUE, bf.attackerMatch());
        assertFalse(bf.overestimate());
    }

    @Test
    void missing_attacker_verdict_yields_null_match() {
        CollectedWindow window = new CollectedWindow(
                List.of(attack("s1", "ab-x", "SSRF", "T1190", 1_000, GroundTruthOutcome.SUCCEEDED, null)),
                List.of(), Map.of()); // 맵 비어 있음 → attackerVerdict 없음

        ScenarioResult r = run(window, mock(VerdictRepository.class)).results().get(0);
        assertNull(r.attackerVerdict(), "fact 없으면 null");
        assertNull(r.attackerMatch(), "attacker 없으면 match=null");
        assertFalse(r.overestimate());
    }

    @Test
    void gt_unknown_yields_uncertain_and_null_match() {
        CollectedWindow window = new CollectedWindow(
                List.of(attack("x1", "ab-x", "SSRF", "T1190", 1_000, GroundTruthOutcome.UNKNOWN, null)),
                List.of(), Map.of());

        ScenarioResult r = run(window, mock(VerdictRepository.class)).results().get(0);
        assertEquals(Verdict.UNCERTAIN, r.verdict());
        assertNull(r.attackerMatch());
    }

    @Test
    void representative_rid_is_first_member_and_opId_propagated() {
        CollectedWindow window = new CollectedWindow(
                List.of(attack("rid-rep", "ab-x", "SSRF", "T1190", 1_000, GroundTruthOutcome.SUCCEEDED, null)),
                List.of(), Map.of(new PawAbility(PAW, "ab-x"), AttackOutcome.SUCCEEDED));

        PerRunSummary summary = run(window, mock(VerdictRepository.class));
        assertEquals("op-1", summary.opId());
        ScenarioResult r = summary.results().get(0);
        assertEquals("op-1", r.opId());
        assertEquals("rid-rep", r.rid()); // memberCorrelationIds().get(0)
    }
}
