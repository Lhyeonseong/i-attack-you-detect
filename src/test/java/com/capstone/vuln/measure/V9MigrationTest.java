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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V8 → V9 (ADR-S4-01 v2.0): benign_endpoint 에 login 행 추가 + M14a·M14b definition_version 상수만 v1.9→v2.0.
 * 뷰 로직·컬럼·분모, ATTACK 쪽 뷰·함수·테이블·기존 스냅샷, M14 값(definition_version 제외)은 완전 불변.
 * 전용 컨테이너(V8 까지만 올린 뒤 비교 대상을 만들고 V9 적용).
 */
class V9MigrationTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG, "8");
        JDBC = new JdbcTemplate(DS);
    }

    private static final String DIGEST = "{\"wazuh_rules\":\"w9\"}";
    private static final List<String> ATTACK_VIEWS = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation",
            "v_metric_h2", "v_metric_coverage_unit", "v_metric_coverage", "v_metric_attacker", "v_metric_m07a",
            "v_metric_m13");

    private static List<String> dump(String sql, Object... args) {
        List<String> out = new ArrayList<>();
        JDBC.queryForList(sql, args).forEach(r -> out.add(r.toString()));
        out.sort(null);
        return out;
    }

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

    @Test
    void v9AddsLoginEndpointAndBumpsDefinitionVersionOnly() {
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

        assertEquals(3, JDBC.queryForObject("SELECT count(*) FROM validation.benign_endpoint", Integer.class),
                "V8 까지는 웹 3행(login 없음)");
        List<String> integrity = dump("SELECT run_id, label, kind, status, expected_attempts, expected_controls, "
                + "actual_attack, actual_control, r10_status, r10_reason, benign_loaded, benign_matched FROM validation.v_run_integrity");
        Map<String, List<String>> attackViews = new LinkedHashMap<>();
        ATTACK_VIEWS.forEach(v -> attackViews.put(v, dump("SELECT * FROM validation." + v + " WHERE run_id = ?", attack)));
        List<String> snapshots = dump("SELECT * FROM validation.metric_snapshot");
        List<String> m14a = dumpWithoutDefinition("v_metric_m14a", web);
        List<String> m14b = dumpWithoutDefinition("v_metric_m14b", web);

        ValidationDbFixture.migrateTo(DS, "9");

        assertEquals("9", JDBC.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class));
        assertEquals(1, JDBC.queryForObject("SELECT count(*) FROM validation.benign_endpoint WHERE endpoint = '/api/auth/login' "
                + "AND scenario = 'BRUTE_FORCE' AND param = 'username'", Integer.class), "login 행 추가(BRUTE_FORCE·username)");
        assertEquals(integrity, dump("SELECT run_id, label, kind, status, expected_attempts, expected_controls, "
                + "actual_attack, actual_control, r10_status, r10_reason, benign_loaded, benign_matched FROM validation.v_run_integrity"));
        ATTACK_VIEWS.forEach(v -> assertEquals(attackViews.get(v),
                dump("SELECT * FROM validation." + v + " WHERE run_id = ?", attack), v));
        assertEquals(snapshots, dump("SELECT * FROM validation.metric_snapshot"), "기존 스냅샷 불변");
        assertEquals(m14a, dumpWithoutDefinition("v_metric_m14a", web), "M14a 값은 definition_version 빼면 불변");
        assertEquals(m14b, dumpWithoutDefinition("v_metric_m14b", web), "M14b 값은 definition_version 빼면 불변");
        assertEquals(List.of("ADR-S4-01 v2.0"), JDBC.queryForList("SELECT DISTINCT definition_version FROM "
                + "(SELECT definition_version FROM validation.v_metric_m14a UNION SELECT definition_version "
                + "FROM validation.v_metric_m14b) x", String.class));

        // v2.0 스냅샷 가능(기존 v1.9 스냅샷과 definition_version 다르므로 중복 아님)
        int rows = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, web);
        assertEquals(9, rows, "M14a 엔드포인트 2 × 통제 3 + M14b 통제 3");
        assertTrue(JDBC.queryForObject("SELECT bool_and(definition_version = 'ADR-S4-01 v2.0') FROM "
                + "validation.metric_snapshot WHERE run_id = ?", Boolean.class, web), "login/web 스냅샷 definition_version v2.0");
    }
}
