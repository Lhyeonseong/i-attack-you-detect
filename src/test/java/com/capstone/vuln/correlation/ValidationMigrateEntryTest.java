package com.capstone.vuln.correlation;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * migrate 전용 진입점({@link ValidationMigrateIT#migrateAndReport})을 운영과 같은 "V1 만 적용 + S3 행" 상태에서 검증.
 * S4-2 V3 는 run_id NOT NULL 을 걸기 전에 NULL 행을 세어 있으면 실패해야 하고(백필 먼저), 실패해도 행은 보존돼야 한다.
 * 테스트마다 새 database 를 만든다(Flyway 상태 격리).
 */
@Testcontainers
class ValidationMigrateEntryTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);

    private static final String VALIDATION_PASSWORD = UUID.randomUUID().toString();

    @BeforeAll
    static void createRoles() throws Exception {
        psql(PG.getDatabaseName(), "CREATE ROLE vulnapp LOGIN NOSUPERUSER");
        PG.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_role.sql"), "/tmp/validation_role.sql");
    }

    private static void psql(String db, String sql) throws Exception {
        ExecResult r = PG.execInContainer("psql", "-v", "ON_ERROR_STOP=1", "-U", PG.getUsername(), "-d", db, "-c", sql);
        assertEquals(0, r.getExitCode(), r.getStderr());
    }

    /** 새 database + 부트스트랩 + V1 만 적용 + S3 행 1개(run_id NULL) — 운영 S4-1 이전 상태 */
    private static DataSource freshDatabaseAtV1() throws Exception {
        String db = "m" + UUID.randomUUID().toString().replace("-", "");
        psql(PG.getDatabaseName(), "CREATE DATABASE " + db);
        ExecResult r = PG.execInContainer("psql", "-U", PG.getUsername(), "-d", db,
                "-v", "valpw=" + VALIDATION_PASSWORD, "-v", "app_role=vulnapp", "-f", "/tmp/validation_role.sql");
        assertEquals(0, r.getExitCode(), r.getStderr());

        DataSource ds = new DriverManagerDataSource(
                PG.getJdbcUrl().replace("/" + PG.getDatabaseName(), "/" + db), "validation_rw", VALIDATION_PASSWORD);
        migrateTo(ds, "1");
        new JdbcTemplate(ds).update("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, verdict, initial_verdict, detection_status,
                    gt_outcome, overestimate, best_confidence, late_detection, spray_account_count, engine_version)
                VALUES ('unit:s3', 'SINGLE', 'SUCCEEDED_MISSED', 'SUCCEEDED_MISSED', 'NOT_DETECTED', 'SUCCEEDED',
                    false, 1.0, false, 0, 's3-v1')""");
        return ds;
    }

    private static void migrateTo(DataSource ds, String target) {
        Flyway.configure().dataSource(ds).schemas("validation").defaultSchema("validation").createSchemas(false)
                .locations("classpath:db/validation").target(target).load().migrate();
    }

    private static int maxSuccessfulVersion(JdbcTemplate jdbc) {
        return jdbc.queryForObject(
                "SELECT max(version::int) FROM validation.flyway_schema_history WHERE success", Integer.class);
    }

    @Test
    void v3RefusesWhileRunIdNullRowsRemainAndKeepsThem() throws Exception {
        DataSource ds = freshDatabaseAtV1();
        JdbcTemplate jdbc = new JdbcTemplate(ds);

        RuntimeException e = assertThrows(RuntimeException.class, () -> ValidationMigrateIT.migrateAndReport(ds));
        String message = String.valueOf(e.getMessage()) + " " + String.valueOf(e.getCause());
        assertTrue(message.contains("run_id NULL 1행"), message);

        assertEquals(2, maxSuccessfulVersion(jdbc), "V2 까지만 적용, V3 는 롤백");
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM validation.verdict_result", Integer.class));
        assertEquals("YES", jdbc.queryForObject("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'verdict_result' AND column_name = 'run_id'""",
                String.class));
    }

    @Test
    void v3SucceedsOnceEveryVerdictIsAttributedToARun() throws Exception {
        DataSource ds = freshDatabaseAtV1();
        JdbcTemplate jdbc = new JdbcTemplate(ds);
        migrateTo(ds, "2");
        // 백필과 같은 순서: run 1개 → 기존 행 귀속
        UUID runId = TestRuns.openTestRun(jdbc, 1, 0);
        jdbc.update("UPDATE validation.verdict_result SET run_id = ?", runId);

        ValidationMigrateIT.Report report = ValidationMigrateIT.migrateAndReport(ds);

        assertEquals(List.of("1", "2"), report.before());
        assertEquals(List.of("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"), report.after());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM validation.verdict_result", Integer.class));
        assertEquals("NO", jdbc.queryForObject("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'verdict_result' AND column_name = 'run_id'""",
                String.class));

        ValidationMigrateIT.Report again = ValidationMigrateIT.migrateAndReport(ds);
        assertEquals(List.of("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"), again.after(), "멱등");
    }
}
