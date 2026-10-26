package com.capstone.vuln.measure;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.Correlation;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.OperationLink;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import com.capstone.vuln.correlation.VerdictResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * S4-1b — 측정 경로 op_id: OperationResolver(Caldera 링크) 결과와 runOnce opId 가 일치할 때만 확정.
 * 불일치·Caldera 실패·op 시간 범위 밖은 미해석(paw 키, resolved=false) 그대로 두고 측정은 계속한다.
 */
class MeasurementHarnessOpIdTest {

    private static final long BASE = 1_000_000_000_000L;
    private static final String PAW = "mcukpa";
    private static final String SSRF = "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
    private static final String PT = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String OP = "11111111-aaaa-4bbb-8ccc-000000000001";
    private static final String OTHER_OP = "22222222-aaaa-4bbb-8ccc-000000000002";
    private static final UUID RUN_ID = UUID.fromString("00000000-0000-0000-0000-0000000000c3");

    private static final Instant ATTACK_TIME = Instant.ofEpochMilli(BASE);
    private static final Instant OP_FINISH = Instant.ofEpochMilli(BASE + 60_000);

    private ListAppender<ILoggingEvent> logs;
    private Logger harnessLogger;

    @BeforeEach
    void captureLogs() {
        harnessLogger = (Logger) LoggerFactory.getLogger(MeasurementHarness.class);
        logs = new ListAppender<>();
        logs.start();
        harnessLogger.addAppender(logs);
    }

    @AfterEach
    void detachLogs() {
        harnessLogger.detachAppender(logs);
    }

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

    private static AttackEvent event(String rid, String ability, String scenario, long offsetMs, GroundTruthOutcome gt) {
        return new AttackEvent(new CorrelationKey(PAW, ability, rid), scenario, "T1190",
                Instant.ofEpochMilli(BASE + offsetMs), "172.20.0.1", "/x", null, gt);
    }

    private static final List<AttackEvent> IN_RANGE = List.of(
            event("ssrf-1", SSRF, "SSRF", 1_000, GroundTruthOutcome.SUCCEEDED),
            event("ssrf-ctl", SSRF, "SSRF", 1_200, GroundTruthOutcome.FAILED),
            event("pt-1", PT, "PATH_TRAVERSAL", 2_000, GroundTruthOutcome.SUCCEEDED));

    /** 두 ability 모두 [BASE-10s, BASE+60s] 에 opId 링크가 있는 가짜 Caldera */
    private static OperationResolver caldera(String opId) {
        Instant decide = Instant.ofEpochMilli(BASE - 10_000);
        Instant finish = Instant.ofEpochMilli(BASE + 60_000);
        return new OperationResolver(() -> List.of(
                new OperationLink(opId, PAW, SSRF, decide, finish),
                new OperationLink(opId, PAW, PT, decide, finish)));
    }

    private record Saved(List<Correlation> correlations, List<VerdictResult> verdicts) {
    }

    @SuppressWarnings("unchecked")
    private static Saved measure(List<AttackEvent> attacks, OperationResolver resolver) {
        VerdictRepository repo = mock(VerdictRepository.class);
        MeasurementHarness harness = new MeasurementHarness(
                new FixedCollector(new CollectedWindow(attacks, List.of(), Map.of())),
                new CorrelationEngine(), new VerdictEngine(), repo, resolver);
        harness.measure(RUN_ID, OP, ATTACK_TIME, OP_FINISH);

        ArgumentCaptor<List<Correlation>> correlations = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<VerdictResult>> verdicts = ArgumentCaptor.forClass(List.class);
        verify(repo, times(1)).save(eq(RUN_ID), correlations.capture(), verdicts.capture(), anyMap());
        return new Saved(correlations.getValue(), verdicts.getValue());
    }

    private List<String> warnings() {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void resolverAgreeingWithRunOnceRecordsOperationUuid() {
        Saved saved = measure(IN_RANGE, caldera(OP));

        assertEquals(3, saved.correlations().size());
        for (Correlation c : saved.correlations()) {
            assertTrue(c.isOpIdResolved(), c.getCorrelationKey());
            assertEquals(OP, c.getOpId());
            assertEquals(PAW, c.getKey().agentPaw(), "alert 매칭용 paw 는 보존");
        }
    }

    @Test
    void mismatchKeepsUnresolvedLogsOneLineAndDoesNotChangeVerdicts() {
        Saved agreed = measure(IN_RANGE, caldera(OP));
        logs.list.clear();

        Saved mismatched = measure(IN_RANGE, caldera(OTHER_OP));

        for (Correlation c : mismatched.correlations()) {
            assertFalse(c.isOpIdResolved(), c.getCorrelationKey());
            assertEquals(PAW, c.getOpId(), "runOnce 값도 resolver 값도 기록하지 않는다(미해석 = paw → DB op_id NULL)");
        }
        List<String> lines = warnings();
        assertEquals(1, lines.size(), lines.toString());
        assertTrue(lines.get(0).contains(OP) && lines.get(0).contains(OTHER_OP), lines.get(0));
        assertEquals(agreed.verdicts(), mismatched.verdicts(), "op 귀속은 판정에 영향 없음");
    }

    @Test
    void calderaFailureFallsBackToPawAndMeasurementContinues() {
        OperationResolver down = new OperationResolver(() -> {
            throw new IllegalStateException("caldera unreachable");
        });

        Saved saved = measure(IN_RANGE, down);

        assertEquals(3, saved.correlations().size());
        saved.correlations().forEach(c -> assertFalse(c.isOpIdResolved()));
    }

    @Test
    void eventsOutsideOperationTimeRangeAreNotResolved() {
        // 링크는 BASE-10s 부터 덮지만 op 범위는 [attackTime, opFinish] — 그 전 이벤트는 다른 op 혼입 가능성
        List<AttackEvent> attacks = List.of(
                event("early", SSRF, "SSRF", -5_000, GroundTruthOutcome.SUCCEEDED),
                event("in", PT, "PATH_TRAVERSAL", 2_000, GroundTruthOutcome.SUCCEEDED));

        Saved saved = measure(attacks, caldera(OP));

        Map<String, Boolean> resolvedByKey = new java.util.HashMap<>();
        saved.correlations().forEach(c -> resolvedByKey.put(c.getCorrelationKey(), c.isOpIdResolved()));
        assertEquals(Map.of("early", false, "in", true), resolvedByKey);
    }
}
