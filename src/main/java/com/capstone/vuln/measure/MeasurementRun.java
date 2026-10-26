package com.capstone.vuln.measure;

import java.time.Instant;
import java.util.UUID;

/**
 * measurement_run 1행 — 측정 실행 1회 (R4: 지표는 run 단위로만).
 *
 * <p>gitDirty 는 Boolean 이지만 NULL(알 수 없음)은 백필 run 전용이다. 하네스가 여는 run 은
 * {@link #open} 으로만 만들고(GitState 의 dirty 는 primitive), 저장소도 NULL 을 거부한다.
 */
public record MeasurementRun(UUID runId,
                             String label,
                             Kind kind,
                             Status status,
                             Instant startedAt,
                             Instant endedAt,
                             String gitCommit,
                             Boolean gitDirty,
                             String rulesDigestJson,
                             Integer expectedAttempts,
                             Integer expectedControls,
                             String notes) {

    public enum Kind { ATTACK, BENIGN }

    public enum Status { OPEN, CLOSED }

    public static MeasurementRun open(String label, Kind kind, Instant startedAt, GitState git,
                                      RulesDigest digest, int expectedAttempts, int expectedControls) {
        return new MeasurementRun(UUID.randomUUID(), label, kind, Status.OPEN, startedAt, null,
                git.commit(), git.dirty(), digest.toJson(), expectedAttempts, expectedControls, null);
    }
}
