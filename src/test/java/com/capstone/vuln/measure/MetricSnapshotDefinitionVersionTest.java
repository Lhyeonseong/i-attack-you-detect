package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T9 — definition_version = 원 지표 뷰들의 값 (ADR-S4-01 v1.6 R13 e).
 * 뷰마다 값이 다르면 거부하고(메시지에 값 목록), 모든 뷰가 새 정의로 바뀌면 새 definition_version 행으로 추가된다(R7·R13 d).
 * 뷰 정의를 바꾸므로 공유 컨테이너가 아닌 이 클래스 전용 컨테이너를 쓴다.
 */
class MetricSnapshotDefinitionVersionTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        JDBC = new JdbcTemplate(ValidationDbFixture.bootstrap(PG));
    }

    private static final String NEXT = "ADR-S4-01 v9.9-test";
    private static final List<String> SNAPSHOT_VIEWS = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation",
            "v_metric_h2", "v_metric_coverage", "v_metric_attacker", "v_metric_m07a", "v_metric_m13");

    /** 뷰 정의의 definition_version 상수만 바꿔 다시 만든다 (열 목록 그대로 — CREATE OR REPLACE VIEW) */
    private static void redefine(String view) {
        String def = JDBC.queryForObject("SELECT pg_get_viewdef(?::regclass, true)", String.class, "validation." + view);
        assertTrue(def.contains("'" + MetricFixture.DEF_VERSION + "'"), view);
        JDBC.execute("CREATE OR REPLACE VIEW validation." + view + " AS "
                + def.replace("'" + MetricFixture.DEF_VERSION + "'", "'" + NEXT + "'"));
    }

    private static int rows(UUID run, String definitionVersion) {
        return JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot WHERE run_id = ? "
                + "AND definition_version = ?", Integer.class, run, definitionVersion);
    }

    @Test
    void t9MixedDefinitionVersionsAreRefusedAndANewUniformVersionIsAdded() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        int first = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        assertEquals(first, rows(run, MetricFixture.DEF_VERSION));

        // 정의 개정 도중(일부 뷰만 새 버전) — 거부, 메시지에 두 값
        redefine("v_metric_mttd");
        DataAccessException mixed = assertThrows(DataAccessException.class,
                () -> JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run));
        String message = mixed.getMostSpecificCause().getMessage();
        assertTrue(message.contains(MetricFixture.DEF_VERSION) && message.contains(NEXT), message);
        assertEquals(0, rows(run, NEXT));

        // 모든 뷰가 새 정의 — 새 definition_version 행으로 추가, 이전 버전 행은 그대로
        SNAPSHOT_VIEWS.stream().filter(v -> !"v_metric_mttd".equals(v)).forEach(MetricSnapshotDefinitionVersionTest::redefine);
        int next = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        assertEquals(first, next);
        assertEquals(next, rows(run, NEXT));
        assertEquals(first, rows(run, MetricFixture.DEF_VERSION));
    }
}
