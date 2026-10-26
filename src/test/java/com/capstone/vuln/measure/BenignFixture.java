package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

/**
 * S4-5 V7 BENIGN run 픽스처 — OPEN BENIGN run 에 benign_request·benign_result 를 쌓고 닫는다.
 * 요청은 엔드포인트별로 n 건(대조 성공 = matched_rid 있음), FP 는 앞에서부터 지정한 수만큼 alerted.
 */
final class BenignFixture {

    static final Instant T0 = Instant.parse("2026-10-22T01:00:00Z");

    private final JdbcTemplate jdbc;
    final UUID runId;
    private int seq;

    BenignFixture(JdbcTemplate jdbc, String rulesDigestJson) {
        this.jdbc = jdbc;
        this.runId = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO validation.measurement_run (run_id, label, kind, status, started_at, git_commit, git_dirty,
                    rules_digest, expected_attempts, expected_controls)
                VALUES (?, ?, 'BENIGN', 'OPEN', now(), 'test', false, ?::jsonb, NULL, 0)""",
                runId, "benign-" + runId, rulesDigestJson);
    }

    BenignFixture(JdbcTemplate jdbc) {
        this(jdbc, "{}");
    }

    /**
     * endpoint 요청 n 건. matched 건만 rid 를 갖는다. 대조된 요청마다 APP_RULE·NIDS 결과 행(BACKEND_CORR 는 웹 엔드포인트 비대상),
     * 앞 appFp 건은 APP_RULE alerted(알림 1개 100210), 앞 nidsFp 건은 NIDS alerted(알림 1개 1000013).
     */
    BenignFixture requests(String endpoint, int n, int matched, int appFp, int nidsFp) {
        for (int i = 0; i < n; i++) {
            int s = ++seq;
            Timestamp at = Timestamp.from(T0.plusMillis(250L * s));
            jdbc.update("""
                    INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status,
                        matched_rid)
                    VALUES (?, ?, ?, ?, ?, ?, 200, ?)""",
                    runId, s, endpoint, "d" + s, at, at, i < matched ? "rid-" + runId + "-" + s : null);
            if (i >= matched) {
                continue;
            }
            result(s, "APP_RULE", i < appFp ? "{100210}" : "{}");
            result(s, "NIDS", i < nidsFp ? "{1000013}" : "{}");
        }
        return this;
    }

    void result(int s, String control, String ruleIds) {
        jdbc.update("""
                INSERT INTO validation.benign_result (run_id, seq, control, alerted, linked_rule_ids, alert_count,
                    recorded_rule_ids)
                VALUES (?, ?, ?, cardinality(?::text[]) > 0, ?::text[], cardinality(?::text[]), '{}')""",
                runId, s, control, ruleIds, ruleIds, ruleIds);
    }

    /** expected_attempts = 지정 값(null 이면 EXPECTED_MISSING), close=false 면 OPEN 유지 */
    UUID close(Integer expected, boolean close) {
        jdbc.update("UPDATE validation.measurement_run SET expected_attempts = ? WHERE run_id = ?", expected, runId);
        if (close) {
            jdbc.update("UPDATE validation.measurement_run SET status = 'CLOSED', ended_at = now() WHERE run_id = ?", runId);
        }
        return runId;
    }

    int size() {
        return seq;
    }
}
