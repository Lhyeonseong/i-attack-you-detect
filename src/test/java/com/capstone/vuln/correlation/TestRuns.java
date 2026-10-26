package com.capstone.vuln.correlation;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

/**
 * 테스트용 run·verdict 헬퍼 (컨테이너 기동 부작용 없음 — 어느 DataSource 든 JdbcTemplate 로 받는다).
 * S4-2 부터 verdict_result.run_id NOT NULL 이라 모든 verdict 는 OPEN run 에 넣는다.
 */
public final class TestRuns {

    private TestRuns() {
    }

    /** OPEN 테스트 run (git_dirty=false, digest '{}') — verdict INSERT 는 OPEN run 에만 가능 */
    public static UUID openTestRun(JdbcTemplate jdbc, Integer expectedAttempts, Integer expectedControls) {
        UUID runId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO validation.measurement_run (run_id, label, kind, status, started_at, git_commit, git_dirty,
                    rules_digest, expected_attempts, expected_controls)
                VALUES (?, ?, 'ATTACK', 'OPEN', now(), 'test', false, '{}'::jsonb, ?, ?)""",
                runId, "test-" + runId, expectedAttempts, expectedControls);
        return runId;
    }

    public static UUID openTestRun(JdbcTemplate jdbc) {
        return openTestRun(jdbc, null, null);
    }

    /** OPEN → CLOSED (verdict 를 다 넣은 뒤 호출 — CLOSED run 에는 INSERT 불가) */
    public static void closeTestRun(JdbcTemplate jdbc, UUID runId) {
        jdbc.update("UPDATE validation.measurement_run SET status = 'CLOSED', ended_at = now() WHERE run_id = ?", runId);
    }

    /** 최소 verdict 1행 (판정 값은 의미 없음 — 역할·run 귀속만 쓰는 테스트용) */
    public static void insertVerdict(JdbcTemplate jdbc, UUID runId, String unitKey, String attemptRole) {
        jdbc.update("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, verdict, initial_verdict, detection_status,
                    gt_outcome, overestimate, best_confidence, late_detection, spray_account_count, engine_version,
                    run_id, attempt_role)
                VALUES (?, 'SINGLE', 'SUCCEEDED_MISSED', 'SUCCEEDED_MISSED', 'NOT_DETECTED', 'SUCCEEDED',
                    false, 1.0, false, 0, 'test', ?, ?)""", unitKey, runId, attemptRole);
    }
}
