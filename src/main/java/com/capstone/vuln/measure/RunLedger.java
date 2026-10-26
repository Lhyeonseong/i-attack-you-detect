package com.capstone.vuln.measure;

import java.util.UUID;

/** 캠페인의 run 수명주기 seam — 운영은 {@link MeasurementRunRecorder}, 테스트는 가짜 */
public interface RunLedger {

    /** run OPEN — expected_* = manifest × plannedOperations */
    UUID open(String label, int plannedOperations);

    /** run CLOSED + ended_at */
    void close(UUID runId);

    /** R10 검사 (실제 ATTACK·CONTROL vs expected, run OPEN 이면 INCOMPLETE) */
    SampleIntegrity.Result integrity(UUID runId);
}
