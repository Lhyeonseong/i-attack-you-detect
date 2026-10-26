package com.capstone.vuln.measure;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * 하네스 run 기록 — open 시 git 상태·rules_digest·expected_* 를 남기고, close 시 CLOSED·ended_at.
 * expected_attempts / expected_controls = manifest 의 op당 단위 합 × 계획 operation 수 (R10).
 */
public class MeasurementRunRecorder implements RunLedger {

    private final MeasurementRunRepository repository;
    private final GitStateSource git;
    private final Supplier<RulesDigest> digest;
    private final AttemptManifest manifest;
    private final TimeSource time;

    public MeasurementRunRecorder(MeasurementRunRepository repository,
                                  GitStateSource git,
                                  Supplier<RulesDigest> digest,
                                  AttemptManifest manifest,
                                  TimeSource time) {
        this.repository = repository;
        this.git = git;
        this.digest = digest;
        this.manifest = manifest;
        this.time = time;
    }

    @Override
    public UUID open(String label, int plannedOperations) {
        MeasurementRun run = MeasurementRun.open(label, MeasurementRun.Kind.ATTACK, now(), git.read(), digest.get(),
                manifest.attacksPerOperation() * plannedOperations,
                manifest.controlsPerOperation() * plannedOperations);
        repository.open(run);
        return run.runId();
    }

    @Override
    public void close(UUID runId) {
        repository.close(runId, now());
    }

    @Override
    public SampleIntegrity.Result integrity(UUID runId) {
        return repository.integrity(runId).orElseThrow(() -> new IllegalStateException("run 없음: " + runId));
    }

    private Instant now() {
        return Instant.ofEpochMilli(time.millis());
    }
}
