package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 캠페인 반복 흐름 검증 — runOnce → 관찰 대기 → measure 순서/격리, truncate 옵션, 집계 결과 반환.
 * 가짜 시계(실제 sleep 없음), 실제 runOnce/measure 는 가짜로 대체(엔진 호출은 2b 에서 검증).
 */
class MeasurementCampaignTest {

    private static final Duration OBSERVE = Duration.ofSeconds(30);

    private final List<String> events = new ArrayList<>();

    private static final class FakeTime implements TimeSource {
        private long ms;

        @Override
        public long millis() {
            return ms;
        }
    }

    private final class FakeRunner extends OperationRunner {
        private int count;

        FakeRunner() {
            super(null, null, null, null, null, null, null, null, null);
        }

        @Override
        public RunResult runOnce(String name) {
            events.add("runOnce:" + name);
            return new RunResult("op-" + (count++), "finished", 1000);
        }
    }

    private final class FakeHarness extends MeasurementHarness {
        FakeHarness() {
            super(null, null, null, null, null);
        }

        @Override
        public PerRunSummary measure(UUID runId, String opId, Instant attackTime, Instant opFinish) {
            events.add("measure:" + opId);
            measuredRunIds.add(runId);
            return new PerRunSummary(opId, List.of());
        }
    }

    private final class FakeSource implements VerdictSampleSource {
        @Override
        public List<VerdictSample> loadSamples(UUID runId) {
            loadedRunId = runId;
            return List.of(new VerdictSample("SSRF", false, Boolean.TRUE, false));
        }

        @Override
        public void truncateAll() {
            events.add("truncate");
        }
    }

    private final class FakeWriter extends GateReportWriter {
        private GateReport captured;

        @Override
        public Path write(GateReport report, Path dir) {
            this.captured = report;
            return Path.of("report.md");
        }
    }

    /** run 수명주기 가짜 — events 와 분리해 기록(기존 순서 단언 유지) */
    private final class FakeLedger implements RunLedger {
        private final UUID runId = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
        private final List<String> calls = new ArrayList<>();

        @Override
        public UUID open(String label, int plannedOperations) {
            calls.add("open:" + plannedOperations + ":events=" + events.size());
            return runId;
        }

        @Override
        public void close(UUID id) {
            calls.add("close:events=" + events.size());
        }

        @Override
        public SampleIntegrity.Result integrity(UUID id) {
            return new SampleIntegrity.Result(SampleIntegrity.Status.VALID, null);
        }
    }

    private final List<UUID> measuredRunIds = new ArrayList<>();
    private UUID loadedRunId;
    private final FakeLedger ledger = new FakeLedger();

    private MeasurementCampaign campaign(FakeTime time, FakeWriter writer, FakeSource source) {
        Sleeper sleeper = d -> {
            events.add("sleep:" + d.toSeconds());
            time.ms += d.toMillis();
        };
        return new MeasurementCampaign(new FakeRunner(), new FakeHarness(), source, ledger, writer,
                OBSERVE, Path.of("detections/measurements"), time, sleeper);
    }

    @Test
    void runs_n_iterations_with_observation_wait_between_runOnce_and_measure() {
        FakeWriter writer = new FakeWriter();
        campaign(new FakeTime(), writer, new FakeSource()).run(2, false);

        assertEquals(List.of(
                "runOnce:S4-measure #1 1970-01-01T00:00:00Z", "sleep:30", "measure:op-0",
                "runOnce:S4-measure #2 1970-01-01T00:00:30Z", "sleep:30", "measure:op-1"),
                events);
        assertFalse(events.contains("truncate"), "기본 append — truncate 호출 안 함");
    }

    @Test
    void truncate_option_clears_before_loop() {
        campaign(new FakeTime(), new FakeWriter(), new FakeSource()).run(1, true);
        assertEquals("truncate", events.get(0), "truncate 는 루프 전에 1회");
        assertTrue(events.contains("runOnce:S4-measure #1 1970-01-01T00:00:00Z"));
    }

    @Test
    void returns_gate_report_from_loaded_samples() {
        FakeWriter writer = new FakeWriter();
        GateReport report = campaign(new FakeTime(), writer, new FakeSource()).run(1, false);
        // 표본 1건(conclusive<20) → INCONCLUSIVE, 리포트가 writer 로도 전달됨
        assertEquals(GateResult.INCONCLUSIVE, report.overall());
        assertEquals(1, report.totalSamples());
        assertEquals(report, writer.captured);
    }

    @Test
    void opens_one_run_before_loop_and_closes_after_and_scopes_samples_to_it() {
        campaign(new FakeTime(), new FakeWriter(), new FakeSource()).run(2, false);

        // 계획 op 수(2)로 open → 루프(6 이벤트) 뒤 close
        assertEquals(List.of("open:2:events=0", "close:events=6"), ledger.calls);
        assertEquals(List.of(ledger.runId, ledger.runId), measuredRunIds, "모든 measure 에 같은 run_id");
        assertEquals(ledger.runId, loadedRunId, "게이트 표본은 이 run 만");
    }
}
