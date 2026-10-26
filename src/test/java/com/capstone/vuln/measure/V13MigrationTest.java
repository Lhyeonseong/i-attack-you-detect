package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class V13MigrationTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG, "12");
        JDBC = new JdbcTemplate(DS);
    }

    @Test
    void v13AddsFinalBenignCorrelationWithoutChangingRawResults() {
        UUID run = UUID.randomUUID();
        OffsetDateTime t = OffsetDateTime.parse("2026-10-24T00:00:00Z");

        JDBC.update("""
                INSERT INTO validation.measurement_run
                (run_id, label, kind, status, started_at, git_commit, git_dirty, rules_digest, expected_attempts, expected_controls)
                VALUES (?, 'v13-test', 'BENIGN', 'OPEN', ?, 'test', false, '{}'::jsonb, 2, 0)
                """, run, t);

        JDBC.update("""
                INSERT INTO validation.benign_request
                (run_id, seq, endpoint, args_digest, sent_at, responded_at, status, matched_rid)
                VALUES
                (?, 1, '/api/auth/login', 'a', ?, ?, 401, 'r1'),
                (?, 2, '/api/auth/login', 'b', ?, ?, 401, 'r2')
                """,
                run, t, t.plusNanos(10000000),
                run, t.plusSeconds(1), t.plusSeconds(1).plusNanos(10000000));

        JDBC.update("""
                INSERT INTO validation.benign_result
                (run_id, seq, control, alerted, linked_rule_ids, alert_count, recorded_rule_ids)
                VALUES
                (?, 1, 'NIDS', true, ARRAY['1000031'], 1, ARRAY[]::text[]),
                (?, 1, 'BACKEND_CORR', false, ARRAY[]::text[], 0, ARRAY['100230']),
                (?, 2, 'NIDS', true, ARRAY['1000031'], 1, ARRAY[]::text[]),
                (?, 2, 'BACKEND_CORR', true, ARRAY['100231'], 1, ARRAY[]::text[])
                """, run, run, run, run);

        List<Map<String, Object>> before = JDBC.queryForList(
                "SELECT seq, control, alerted, linked_rule_ids, alert_count, recorded_rule_ids "
                        + "FROM validation.benign_result WHERE run_id = ? ORDER BY seq, control", run);

        ValidationDbFixture.migrateTo(DS, "13");

        assertEquals("13", JDBC.queryForObject(
                "SELECT version FROM validation.flyway_schema_history WHERE success "
                        + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1",
                String.class));

        List<Map<String, Object>> after = JDBC.queryForList(
                "SELECT seq, control, alerted, linked_rule_ids, alert_count, recorded_rule_ids "
                        + "FROM validation.benign_result WHERE run_id = ? ORDER BY seq, control", run);

        assertEquals(before.toString(), after.toString(), "기존 benign_result 원시 판정은 V13에서 변경되지 않아야 한다");

        Map<String, Object> nidsOnly = JDBC.queryForMap(
                "SELECT * FROM validation.v_benign_final_result WHERE run_id = ? AND seq = 1", run);
        assertTrue((Boolean) nidsOnly.get("nids_alerted"));
        assertFalse((Boolean) nidsOnly.get("backend_corr_alerted"));
        assertFalse((Boolean) nidsOnly.get("final_alerted"));
        assertEquals("NIDS_ONLY", nidsOnly.get("decision_reason"));

        Map<String, Object> sequence = JDBC.queryForMap(
                "SELECT * FROM validation.v_benign_final_result WHERE run_id = ? AND seq = 2", run);
        assertTrue((Boolean) sequence.get("nids_alerted"));
        assertTrue((Boolean) sequence.get("backend_corr_alerted"));
        assertTrue((Boolean) sequence.get("final_alerted"));
        assertEquals("BACKEND_SEQUENCE", sequence.get("decision_reason"));
    }
}
