package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * validation schema 마이그레이션 전용 엔트리포인트 (S4-1a) — 측정·Caldera 호출·데이터 쓰기 없이
 * {@link ValidationSchemaMigrator#migrate} 만 돌린다(Flyway 가 쓰는 flyway_schema_history 1행 제외).
 *
 * <p>기본 build/CI 에서는 돌지 않는다: {@code RUN_VALIDATION_MIGRATE=1} 일 때만.
 * 접속은 CampaignRunnerIT 와 같다 — 127.0.0.1:${POSTGRES_PORT:-5433}/${POSTGRES_DB}, role validation_rw.
 * 실행 명령은 detections/measurements/backfill/RUNBOOK-2026-10-18.md (1).
 */
@EnabledIfEnvironmentVariable(named = "RUN_VALIDATION_MIGRATE", matches = "1")
class ValidationMigrateIT {

    record Report(List<String> before, List<String> after) {
    }

    /** 적용 전 버전 → migrate → 적용 후 버전 */
    static Report migrateAndReport(DataSource validationDataSource) {
        JdbcTemplate jdbc = new JdbcTemplate(validationDataSource);
        List<String> before = appliedVersions(jdbc);
        ValidationSchemaMigrator.migrate(validationDataSource);
        return new Report(before, appliedVersions(jdbc));
    }

    private static List<String> appliedVersions(JdbcTemplate jdbc) {
        Boolean exists = jdbc.queryForObject(
                "SELECT to_regclass('validation.flyway_schema_history') IS NOT NULL", Boolean.class);
        if (!Boolean.TRUE.equals(exists)) {
            return List.of();
        }
        return jdbc.queryForList("""
                SELECT version FROM validation.flyway_schema_history
                WHERE success AND version IS NOT NULL ORDER BY installed_rank""", String.class);
    }

    @Test
    void migrate() {
        String port = System.getenv().getOrDefault("POSTGRES_PORT", "5433");
        String db = System.getenv("POSTGRES_DB");
        String password = System.getenv("VALIDATION_DB_PASSWORD");
        assertTrue(db != null && !db.isBlank(), "POSTGRES_DB 필요");
        assertTrue(password != null && !password.isBlank(), "VALIDATION_DB_PASSWORD 필요");

        DataSource ds = new DriverManagerDataSource(
                "jdbc:postgresql://127.0.0.1:" + port + "/" + db, "validation_rw", password);
        Report report = migrateAndReport(ds);

        System.out.println("MIGRATE>> before=" + report.before() + " after=" + report.after());
        new JdbcTemplate(ds).query("""
                SELECT installed_rank, version, description, installed_by, installed_on, success
                FROM validation.flyway_schema_history ORDER BY installed_rank""",
                rs -> {
                    System.out.printf("MIGRATE>>   rank=%d v=%s %s by=%s on=%s success=%s%n",
                            rs.getInt(1), rs.getString(2), rs.getString(3), rs.getString(4),
                            rs.getString(5), rs.getBoolean(6));
                });
        assertFalse(report.after().isEmpty(), "적용 후 버전이 비어 있으면 안 됨");
    }
}
