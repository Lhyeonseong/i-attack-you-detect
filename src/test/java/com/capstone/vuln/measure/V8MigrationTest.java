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

import static com.capstone.vuln.measure.MetricFixture.a;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * V7 → V8 (ADR-S4-01 v1.9): M14b 비적용 통제 상태를 M13·M14a 와 같은 규칙으로(BACKEND_CORR × 웹 = NO_RULE).
 * 그 밖은 그대로 — ATTACK run 의 v_run_integrity·지표 뷰·스냅샷, M14a 값, M14b APP_RULE·NIDS 값(definition_version 만 v1.9).
 * 전용 컨테이너(V7 까지만 올린 뒤 비교 대상을 만들고 V8 적용).
 */
class V8MigrationTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG, "7");
        JDBC = new JdbcTemplate(DS);
    }

    private static final String DIGEST = "{\"wazuh_rules\":\"w8\"}";
    private static final List<String> ATTACK_VIEWS = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation",
            "v_metric_h2", "v_metric_coverage_unit", "v_metric_coverage", "v_metric_attacker", "v_metric_m07a",
            "v_metric_m13");

    private static List<String> dump(String sql, Object... args) {
        List<String> out = new ArrayList<>();
        JDBC.queryForList(sql, args).forEach(r -> out.add(r.toString()));
        out.sort(null);
        return out;
    }

    /** definition_version 열을 뺀 행 (v1.8 → v1.9 상수만 바뀌는 비교용) */
    private static List<String> dumpWithoutDefinition(String view, UUID run) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> r : JDBC.queryForList("SELECT * FROM validation." + view + " WHERE run_id = ?", run)) {
            Map<String, Object> copy = new LinkedHashMap<>(r);
            copy.remove("definition_version");
            out.add(copy.toString());
        }
        out.sort(null);
        return out;
    }

    private static Map<String, String> statusByControl(UUID run) {
        Map<String, String> out = new LinkedHashMap<>();
        JDBC.queryForList("SELECT control, status FROM validation.v_metric_m14b WHERE run_id = ? ORDER BY control", run)
                .forEach(r -> out.put((String) r.get("control"), (String) r.get("status")));
        return out;
    }

    @Test
    void v8OnlyAlignsM14bInapplicableStatus() {
        UUID attack = new MetricFixture(JDBC).nidsCollected()
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100220").ctl("NIDS", "1000020"))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .close(MetricFixture.Close.VALID);
        JDBC.update("UPDATE validation.measurement_run SET rules_digest = ?::jsonb WHERE run_id = ?", DIGEST, attack);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, attack);
        UUID web = new BenignFixture(JDBC, DIGEST)
                .requests("/api/products/search", 3, 3, 1, 0)
                .requests("/api/preview", 3, 3, 0, 1)
                .close(6, true);

        List<String> integrity = dump("SELECT run_id, label, kind, status, expected_attempts, expected_controls, "
                + "actual_attack, actual_control, r10_status, r10_reason, benign_loaded, benign_matched FROM validation.v_run_integrity");
        Map<String, List<String>> attackViews = new LinkedHashMap<>();
        ATTACK_VIEWS.forEach(v -> attackViews.put(v, dump("SELECT * FROM validation." + v + " WHERE run_id = ?", attack)));
        List<String> snapshots = dump("SELECT * FROM validation.metric_snapshot");
        List<String> m14a = dumpWithoutDefinition("v_metric_m14a", web);
        List<String> m14bApplicable = new ArrayList<>(dumpWithoutDefinition("v_metric_m14b", web));
        m14bApplicable.removeIf(r -> r.contains("control=BACKEND_CORR"));
        assertEquals(Map.of("APP_RULE", "OK", "BACKEND_CORR", "NOT_APPLICABLE", "NIDS", "OK"), statusByControl(web),
                "V7 의 불일치 재현: M14a BACKEND_CORR × 웹 = NO_RULE 인데 M14b = NOT_APPLICABLE");

        ValidationDbFixture.migrateTo(DS, "8"); // V7 → V8 이행만 본다 (V9 이후는 V9MigrationTest)

        assertEquals("8", JDBC.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class));
        assertEquals(integrity, dump("SELECT run_id, label, kind, status, expected_attempts, expected_controls, "
                + "actual_attack, actual_control, r10_status, r10_reason, benign_loaded, benign_matched FROM validation.v_run_integrity"));
        ATTACK_VIEWS.forEach(v -> assertEquals(attackViews.get(v),
                dump("SELECT * FROM validation." + v + " WHERE run_id = ?", attack), v));
        assertEquals(snapshots, dump("SELECT * FROM validation.metric_snapshot"));
        assertEquals(m14a, dumpWithoutDefinition("v_metric_m14a", web));
        List<String> after = new ArrayList<>(dumpWithoutDefinition("v_metric_m14b", web));
        after.removeIf(r -> r.contains("control=BACKEND_CORR"));
        assertEquals(m14bApplicable, after);
        assertEquals(Map.of("APP_RULE", "OK", "BACKEND_CORR", "NO_RULE", "NIDS", "OK"), statusByControl(web));
        assertEquals(List.of("ADR-S4-01 v1.9"), JDBC.queryForList("SELECT DISTINCT definition_version FROM "
                + "(SELECT definition_version FROM validation.v_metric_m14a UNION SELECT definition_version "
                + "FROM validation.v_metric_m14b) x", String.class));

        int rows = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, web);
        assertEquals(9, rows, "M14a 엔드포인트 2 × 통제 3 + M14b 통제 3");
    }
}
