package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.TestRuns;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T4 — validation.v_run_integrity (ADR-S4-01 R10 3상태).
 * reason 우선순위 OPEN → EXPECTED_MISSING → ATTACK_MISMATCH → CONTROL_MISMATCH (불일치가 둘 다면 ATTACK_MISMATCH).
 * 같은 픽스처에서 Java R10 판정(MeasurementRunRecorder.integrity)이 뷰와 같은 결과인지 — 단일 원천.
 * Java reason = "코드 (expected a, actual b)", 코드는 뷰 r10_reason 과 정확히 같다.
 */
class RunIntegrityViewTest extends ValidationDbFixture {

    private final Map<String, UUID> runs = new LinkedHashMap<>();

    @BeforeEach
    void fixtures() {
        truncateRunData();
        runs.put("valid", run(2, 1, 2, 1, true));
        runs.put("attackMismatch", run(2, 1, 1, 1, true));
        runs.put("controlMismatch", run(2, 1, 2, 0, true));
        runs.put("bothMismatch", run(2, 1, 1, 0, true));
        // 합계 3 은 같아도 역할 분포가 다르면 INVALID — 대조군이 공격으로 집계된 경우 (구 SampleIntegrityTest 에서 이관)
        runs.put("totalOnlyMatches", run(2, 1, 3, 0, true));
        runs.put("attemptsMissing", run(null, 1, 2, 1, true));
        runs.put("controlsMissing", run(2, null, 2, 1, true));
        runs.put("open", run(2, 1, 2, 1, false));
        runs.put("closedEmpty", run(2, 1, 0, 0, true));
    }

    /** OPEN 으로 만들고 verdict 를 넣은 뒤 필요하면 CLOSED (CLOSED run 에는 INSERT 불가) */
    private static UUID run(Integer expectedAttempts, Integer expectedControls, int attacks, int controls, boolean close) {
        UUID runId = TestRuns.openTestRun(JDBC, expectedAttempts, expectedControls);
        for (int i = 0; i < attacks; i++) {
            TestRuns.insertVerdict(JDBC, runId, "unit:" + runId + ":a" + i, "ATTACK");
        }
        for (int i = 0; i < controls; i++) {
            TestRuns.insertVerdict(JDBC, runId, "unit:" + runId + ":c" + i, "CONTROL");
        }
        if (close) {
            TestRuns.closeTestRun(JDBC, runId);
        }
        return runId;
    }

    private Map<String, Object> view(String fixture) {
        return JDBC.queryForMap("SELECT * FROM validation.v_run_integrity WHERE run_id = ?", runs.get(fixture));
    }

    private void assertState(String fixture, String status, String reason) {
        Map<String, Object> row = view(fixture);
        assertEquals(status, row.get("r10_status"), fixture);
        assertEquals(reason, row.get("r10_reason"), fixture);
    }

    @Test
    void closedRunMatchingBothCountsIsValid() {
        assertState("valid", "VALID", null);
        Map<String, Object> row = view("valid");
        assertEquals(2L, ((Number) row.get("actual_attack")).longValue());
        assertEquals(1L, ((Number) row.get("actual_control")).longValue());
    }

    @Test
    void mismatchesAndMissingExpectationsAreInvalidWithReason() {
        assertState("attackMismatch", "INVALID", "ATTACK_MISMATCH");
        assertState("controlMismatch", "INVALID", "CONTROL_MISMATCH");
        assertState("bothMismatch", "INVALID", "ATTACK_MISMATCH");
        assertState("totalOnlyMatches", "INVALID", "ATTACK_MISMATCH");
        assertState("attemptsMissing", "INVALID", "EXPECTED_MISSING");
        assertState("controlsMissing", "INVALID", "EXPECTED_MISSING");
    }

    @Test
    void openRunIsIncomplete() {
        assertState("open", "INCOMPLETE", "OPEN");
    }

    @Test
    void runWithoutVerdictsStillHasARow() {
        assertState("closedEmpty", "INVALID", "ATTACK_MISMATCH");
        Map<String, Object> row = view("closedEmpty");
        assertEquals(0L, ((Number) row.get("actual_attack")).longValue());
        assertEquals(0L, ((Number) row.get("actual_control")).longValue());
        assertEquals(runs.size(), JDBC.queryForObject("SELECT count(*) FROM validation.v_run_integrity", Integer.class));
    }

    @Test
    void javaR10JudgementEqualsTheView() {
        MeasurementRunRecorder recorder = new MeasurementRunRecorder(new MeasurementRunRepository(DS),
                () -> new GitState("test", false), () -> { throw new UnsupportedOperationException(); },
                AttemptManifest.ATTACK_VALIDATION_WEB, System::currentTimeMillis);
        for (Map.Entry<String, UUID> e : runs.entrySet()) {
            Map<String, Object> row = view(e.getKey());
            SampleIntegrity.Result java = recorder.integrity(e.getValue());
            assertEquals(row.get("r10_status"), java.status().name(), e.getKey());
            String reason = (String) row.get("r10_reason");
            if (reason == null) {
                assertNull(java.reason(), e.getKey());
            } else {
                assertTrue(java.reason() != null && java.reason().matches("[A-Z_]+ \\(expected .+, actual .+\\)"),
                        e.getKey() + ": java reason=" + java.reason());
                assertEquals(reason, java.reason().substring(0, java.reason().indexOf(" (")), e.getKey());
            }
        }
        assertEquals("ATTACK_MISMATCH (expected attack=2 control=1, actual attack=1 control=0)",
                recorder.integrity(runs.get("bothMismatch")).reason());
    }
}
