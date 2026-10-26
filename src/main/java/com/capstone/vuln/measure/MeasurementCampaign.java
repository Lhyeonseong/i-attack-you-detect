package com.capstone.vuln.measure;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * N회 반복 측정 → 집계 → 게이트 리포트 (S3-5b-3). 실제 20회 본측정은 사람이 tmux 로 n 을 주고 돌린다.
 *
 * <p>1회씩 격리(겹치기 금지, 결정4·DET0080): runOnce → op 완료 → 그 op만 관찰 대기(기본 30s) → measure.
 * 관찰 대기는 마지막 ability(BF) alert 가 인덱서에 searchable 되도록 하는 입력 정합성 장치다.
 * 반복이 끝나면 verdict_result 를 시나리오별로 롤업해 게이트(일치율·과대평가·표본수)를 판정한다.
 * 판정/상관/저장·게이트 임계 비교 외의 계산은 하지 않는다(엔진·GateEvaluator 출력 사용).
 *
 * <p>S4-1: 캠페인 1회 = measurement_run 1개. 루프 전에 OPEN(expected = manifest × n), 모든 measure 에 같은
 * run_id, 루프 후 CLOSED. 게이트 표본은 그 run 의 ATTACK 만. 실패로 중단되면 run 은 OPEN 으로 남는다(미완료 표식).
 */
public class MeasurementCampaign {

    private final OperationRunner runner;
    private final MeasurementHarness harness;
    private final VerdictSampleSource sampleSource;
    private final RunLedger ledger;
    private final GateReportWriter reportWriter;
    private final Duration observationWait;
    private final Path reportDir;
    private final TimeSource time;
    private final Sleeper sleeper;

    public MeasurementCampaign(OperationRunner runner,
                               MeasurementHarness harness,
                               VerdictSampleSource sampleSource,
                               RunLedger ledger,
                               GateReportWriter reportWriter,
                               Duration observationWait,
                               Path reportDir,
                               TimeSource time,
                               Sleeper sleeper) {
        this.runner = runner;
        this.harness = harness;
        this.sampleSource = sampleSource;
        this.ledger = ledger;
        this.reportWriter = reportWriter;
        this.observationWait = observationWait;
        this.reportDir = reportDir;
        this.time = time;
        this.sleeper = sleeper;
    }

    /**
     * n회 측정 후 게이트 리포트 생성.
     *
     * @param n        반복 횟수(본측정 20). 러너는 N 을 인자로 받는다.
     * @param truncate true 면 시작 전 verdict_result/member/history 비움(본측정 전 초기화). 기본 append.
     */
    public GateReport run(int n, boolean truncate) {
        return run("campaign n=" + n + " " + Instant.ofEpochMilli(time.millis()), n, truncate);
    }

    /** @param label measurement_run.label */
    public GateReport run(String label, int n, boolean truncate) {
        if (truncate) {
            sampleSource.truncateAll();
        }
        UUID runId = ledger.open(label, n);
        for (int i = 1; i <= n; i++) {
            Instant attackTime = Instant.ofEpochMilli(time.millis());
            String name = "S4-measure #" + i + " " + attackTime;
            RunResult rr = runner.runOnce(name);
            Instant opFinish = attackTime.plusMillis(rr.durationMs());
            observe(); // op 완료 후 그 op만 관찰 대기 → measure (BF 타이밍 해소)
            harness.measure(runId, rr.opId(), attackTime, opFinish);
        }
        ledger.close(runId);

        GateReport report = GateEvaluator.evaluate(
                sampleSource.loadSamples(runId), Instant.ofEpochMilli(time.millis()));
        Path path = reportWriter.write(report, reportDir);
        print(report, path);
        System.out.println("RUN run_id=" + runId + " R10=" + ledger.integrity(runId));
        return report;
    }

    private void observe() {
        try {
            sleeper.sleep(observationWait);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("관찰 대기 중단됨", e);
        }
    }

    private static void print(GateReport report, Path path) {
        System.out.println("GATE overall=" + report.overall()
                + " totalSamples=" + report.totalSamples()
                + " totalUncertain=" + report.totalUncertain() + " report=" + path);
        for (ScenarioGate g : report.scenarios()) {
            System.out.printf("  %s samples=%d matchRate=%.3f overestimate=%d uncertain=%d -> %s%n",
                    g.scenario(), g.samples(), g.matchRate(), g.overestimateCount(),
                    g.uncertainCount(), g.result());
        }
    }
}
