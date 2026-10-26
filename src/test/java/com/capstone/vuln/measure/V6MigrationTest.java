package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.TestRuns;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V5 → V6 이행 (이 클래스 전용 컨테이너 — V5 까지만 올린 뒤 스냅샷을 찍고 V6 를 적용한다).
 * - detection_link 기존 행 → control = APP_RULE
 * - 기존 지표 뷰 7개는 definition_version 상수만 'ADR-S4-01 v1.4' → 'ADR-S4-01 v1.7' (pg_get_viewdef 비교)
 * - T9: v1.7 스냅샷에 M07a·M13 행 포함, 기존 v1.4 스냅샷(snapshot_rule_version v1.6) 행은 그대로,
 *   기존 지표의 값은 v1.4 행과 같다(입력 변경 없음 — 식 동일)
 */
class V6MigrationTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG, "5");
        JDBC = new JdbcTemplate(DS);
    }

    private static final List<String> REDEFINED = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation",
            "v_metric_h2", "v_metric_coverage_unit", "v_metric_coverage", "v_metric_attacker");
    private static final List<String> VALUE_COLUMNS = List.of("numerator", "denominator", "point_estimate", "ci_lower",
            "ci_upper", "p50_ms", "p95_ms", "overestimate_count", "uncertain_count", "criteria_met", "status",
            "source_view");

    private static Map<String, String> viewDefs() {
        Map<String, String> defs = new HashMap<>();
        for (String v : REDEFINED) {
            defs.put(v, JDBC.queryForObject("SELECT pg_get_viewdef(?::regclass, true)", String.class, "validation." + v));
        }
        return defs;
    }

    private static List<Map<String, Object>> snapshot(UUID run, String def) {
        return JDBC.queryForList("SELECT * FROM validation.metric_snapshot WHERE run_id = ? AND definition_version = ? "
                + "ORDER BY snapshot_id", run, def);
    }

    private static Map<String, Map<String, Object>> byObservation(List<Map<String, Object>> rows) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map<String, Object> r : rows) {
            Map<String, Object> values = new LinkedHashMap<>();
            VALUE_COLUMNS.forEach(c -> values.put(c, r.get(c)));
            out.put(r.get("metric_id") + "|" + r.get("scope_kind") + "|" + r.get("scope_key"), values);
        }
        return out;
    }

    @Test
    void v5DataAndSnapshotSurviveV6AndT9AddsM07aM13() {
        // V5 상태: SQLI 성공·탐지 1건(RID 링크, control 컬럼 없음) — VALID run
        UUID run = TestRuns.openTestRun(JDBC, 1, 0);
        long verdictId = JDBC.queryForObject("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, scenario, technique_id, verdict,
                    initial_verdict, detection_status, gt_outcome, attacker_verdict, attacker_match, overestimate,
                    best_confidence, mttd_ms, late_detection, spray_account_count, engine_version, run_id, attempt_role)
                VALUES ('unit:v5', 'SINGLE', 'SQLI', 'T1190', 'SUCCEEDED_DETECTED', 'SUCCEEDED_DETECTED', 'DETECTED',
                    'SUCCEEDED', 'SUCCEEDED', true, false, 1.0, 1500, false, 0, 's3-v1', ?, 'ATTACK')
                RETURNING id""", Long.class, run);
        long correlationId = JDBC.queryForObject("""
                INSERT INTO validation.correlation (correlation_key, op_id_resolved, scenario, technique_id,
                    attack_time, last_attack_time, observed_until, best_confidence, correlation_source,
                    bf_failure_count, bf_sequence, spray, spray_account_count)
                VALUES ('rid-v5', false, 'SQLI', 'T1190', now(), now(), now(), 1.0, 'RID', 0, false, false, 0)
                RETURNING id""", Long.class);
        JDBC.update("""
                INSERT INTO validation.detection_link (correlation_id, rule_id, technique, alert_time, match_path,
                    confidence, late)
                VALUES (?, '100210', 'T1190', now(), 'RID', 1.0, false)""", correlationId);
        JDBC.update("INSERT INTO validation.verdict_member (verdict_id, correlation_id) VALUES (?, ?)",
                verdictId, correlationId);
        TestRuns.closeTestRun(JDBC, run);

        Map<String, String> v5Defs = viewDefs();
        int v14Rows = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        List<Map<String, Object>> v14Before = snapshot(run, "ADR-S4-01 v1.4");
        assertEquals(v14Rows, v14Before.size());

        ValidationDbFixture.migrateTo(DS, "6"); // V5 → V6 이행만 본다 (V7 이후는 V7MigrationTest)

        assertEquals("6", JDBC.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class));
        assertEquals("APP_RULE", JDBC.queryForObject("SELECT control FROM validation.detection_link", String.class));
        Map<String, String> v6Defs = viewDefs();
        for (String v : REDEFINED) {
            assertTrue(v5Defs.get(v).contains("'ADR-S4-01 v1.4'"), v);
            assertEquals(v5Defs.get(v).replace("'ADR-S4-01 v1.4'", "'ADR-S4-01 v1.7'"), v6Defs.get(v), v);
        }

        int v17Rows = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        List<Map<String, Object>> v17 = snapshot(run, "ADR-S4-01 v1.7");
        assertEquals(v17Rows, v17.size());
        // M07a: (ALL + 시나리오 4) × 센서 2 = 10, M13: 통제 3 × 시나리오 4 = 12
        assertEquals(v14Rows + 22, v17Rows);
        Map<String, Map<String, Object>> new17 = byObservation(v17);
        assertEquals("NOT_COLLECTED", new17.get("M07a_NIDS|ALL|ALL").get("status"));
        assertEquals("NOT_COLLECTED", new17.get("M13_NIDS|SCENARIO|SQLI").get("status"));
        assertEquals(1L, ((Number) new17.get("M13_APP_RULE|SCENARIO|SQLI").get("numerator")).longValue());
        assertEquals(1L, ((Number) new17.get("M13_APP_RULE|SCENARIO|SQLI").get("denominator")).longValue());
        assertEquals("NO_RULE", new17.get("M13_BACKEND_CORR|SCENARIO|SQLI").get("status"));
        for (Map<String, Object> r : v17) {
            assertEquals("ADR-S4-01 v1.6", r.get("snapshot_rule_version"));
            assertEquals("6", r.get("schema_version"));
        }

        // 기존 v1.4 행은 그대로, 기존 지표 값은 v1.7 에서도 같다
        assertEquals(v14Before, snapshot(run, "ADR-S4-01 v1.4"));
        Map<String, Map<String, Object>> old14 = byObservation(v14Before);
        for (Map.Entry<String, Map<String, Object>> e : old14.entrySet()) {
            assertEquals(e.getValue(), new17.get(e.getKey()), e.getKey());
        }
    }
}
