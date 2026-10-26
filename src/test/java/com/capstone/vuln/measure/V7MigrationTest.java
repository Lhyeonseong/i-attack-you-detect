package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * V6 → V7 회귀(B6): 기존 ATTACK run 의 v_run_integrity(기존 10열)·지표 뷰 출력·기존 스냅샷 행이 그대로이고,
 * V7 이후 ATTACK 스냅샷 경로가 V6 와 같은 값을 쓴다. 전용 컨테이너(V6 까지만 올린 뒤 스냅샷을 찍고 V7 적용).
 */
class V7MigrationTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG, "6");
        JDBC = new JdbcTemplate(DS);
    }

    private static final List<String> VIEWS = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation",
            "v_metric_h2", "v_metric_coverage_unit", "v_metric_coverage", "v_metric_attacker", "v_metric_m07a",
            "v_metric_m13");
    private static final String INTEGRITY_COLUMNS = "run_id, label, kind, status, expected_attempts, expected_controls, "
            + "actual_attack, actual_control, r10_status, r10_reason";
    private static final List<String> VALUE_COLUMNS = List.of("definition_version", "numerator", "denominator",
            "point_estimate", "ci_lower", "ci_upper", "p50_ms", "p95_ms", "overestimate_count", "uncertain_count",
            "criteria_met", "status", "source_view", "snapshot_rule_version");

    private static List<String> dump(String sql, Object... args) {
        List<String> out = new ArrayList<>();
        JDBC.queryForList(sql, args).forEach(r -> out.add(r.toString()));
        out.sort(null);
        return out;
    }

    private static Map<String, List<String>> viewDumps(UUID run) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String v : VIEWS) {
            out.put(v, dump("SELECT * FROM validation." + v + " WHERE run_id = ?", run));
        }
        return out;
    }

    private static Map<String, List<Object>> snapshotValues(UUID run) {
        Map<String, List<Object>> out = new LinkedHashMap<>();
        for (Map<String, Object> r : JDBC.queryForList(
                "SELECT * FROM validation.metric_snapshot WHERE run_id = ? ORDER BY metric_id, scope_kind, scope_key", run)) {
            List<Object> values = new ArrayList<>();
            VALUE_COLUMNS.forEach(c -> values.add(r.get(c)));
            out.put(r.get("metric_id") + "|" + r.get("scope_kind") + "|" + r.get("scope_key"), values);
        }
        return out;
    }

    @Test
    void attackOutputsAreUnchangedByV7() {
        UUID before = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        new MetricFixture(JDBC).nidsCollected()
                .add(MetricFixture.a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").ctl("NIDS", "1000020").telemetry(1, 1))
                .close(MetricFixture.Close.INVALID);
        List<String> integrity = dump("SELECT " + INTEGRITY_COLUMNS + " FROM validation.v_run_integrity");
        Map<String, List<String>> views = viewDumps(before);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, before);
        List<String> snapshotRows = dump("SELECT * FROM validation.metric_snapshot");
        Map<String, List<Object>> v6Values = snapshotValues(before);

        ValidationDbFixture.migrateTo(DS, "7"); // V6 → V7 이행만 본다 (V8 이후는 V8MigrationTest)

        assertEquals("7", JDBC.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class));
        assertEquals(integrity, dump("SELECT " + INTEGRITY_COLUMNS + " FROM validation.v_run_integrity"));
        assertEquals(views, viewDumps(before));
        assertEquals(snapshotRows, dump("SELECT " + String.join(", ", columnsExceptPaired())
                + " FROM validation.metric_snapshot"));

        // V7 이후 같은 픽스처 run 의 ATTACK 스냅샷 = V6 스냅샷 값 (snapshot_rule_version 포함)
        UUID after = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, after);
        assertEquals(v6Values, snapshotValues(after));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot WHERE paired_run_id IS NOT NULL",
                Integer.class));
    }

    private static List<String> columnsExceptPaired() {
        return JDBC.queryForList("""
                SELECT column_name FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'metric_snapshot' AND column_name <> 'paired_run_id'
                ORDER BY ordinal_position""", String.class);
    }
}
