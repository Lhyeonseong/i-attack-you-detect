package com.capstone.vuln.correlation;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * validation schema 영속화 (Testcontainers, compose 와 같은 postgres 이미지 — PostgresTestImage)
 * 부트스트랩 SQL(db/bootstrap/validation_role.sql)을 실제 psql 로 컨테이너에 적용해 검증한다.
 */
@Testcontainers
class ValidationPersistenceTest {

    /** compose postgres 이미지와 같은 태그 (POSTGRES_VERSION=16) */
    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);

    /** 운영 vulnuser 는 슈퍼유저라 REVOKE 가 무효 — 여기선 슈퍼유저가 아닌 취약 앱 role 로 분리를 검증한다 (Gap #3) */
    private static final String VULN_APP_ROLE = "vulnapp";
    private static final String VALIDATION_PASSWORD = UUID.randomUUID().toString();
    private static final String VULN_APP_PASSWORD = UUID.randomUUID().toString();

    private static final Instant T0 = Instant.parse("2026-10-13T00:00:00Z");
    private static final String IP = "172.20.0.1";

    private static DataSource validationDs;
    private static JdbcTemplate jdbc;
    private static VerdictRepository repository;

    /** S4-2: run_id NOT NULL — 테스트마다 OPEN run 하나에 저장 */
    private UUID runId;

    @BeforeAll
    static void bootstrap() throws Exception {
        psql("CREATE ROLE " + VULN_APP_ROLE + " LOGIN NOSUPERUSER PASSWORD '" + VULN_APP_PASSWORD + "'");
        PG.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_role.sql"), "/tmp/validation_role.sql");
        // 재실행 안전성: 두 번 적용해도 성공해야 한다
        for (int i = 0; i < 2; i++) {
            ExecResult r = PG.execInContainer("psql", "-U", PG.getUsername(), "-d", PG.getDatabaseName(),
                    "-v", "valpw=" + VALIDATION_PASSWORD, "-v", "app_role=" + VULN_APP_ROLE,
                    "-f", "/tmp/validation_role.sql");
            assertEquals(0, r.getExitCode(), r.getStderr());
        }

        validationDs = new DriverManagerDataSource(PG.getJdbcUrl(), "validation_rw", VALIDATION_PASSWORD);
        ValidationSchemaMigrator.migrate(validationDs);
        jdbc = new JdbcTemplate(validationDs);
        repository = new VerdictRepository(validationDs);
    }

    private static void psql(String sql) throws Exception {
        ExecResult r = PG.execInContainer("psql", "-v", "ON_ERROR_STOP=1",
                "-U", PG.getUsername(), "-d", PG.getDatabaseName(), "-c", sql);
        assertEquals(0, r.getExitCode(), r.getStderr());
    }

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE validation.verdict_history, validation.verdict_member, validation.verdict_result, "
                + "validation.detection_link, validation.correlation RESTART IDENTITY CASCADE");
        runId = TestRuns.openTestRun(jdbc);
    }

    // ---- 입력 헬퍼 (실제 엔진으로 만든다) ----

    private static AttackEvent ssrfAttack() {
        return new AttackEvent(new CorrelationKey("paw-1", "a7f3c1d9", "rid-ssrf"), "SSRF", "T1190",
                T0, IP, "/api/preview", null, GroundTruthOutcome.SUCCEEDED);
    }

    private static AlertEvent ssrfAlert(long offsetMs) {
        return new AlertEvent("100240", "T1190", T0.plusMillis(offsetMs), null,
                null, "paw-1", "a7f3c1d9", IP, "/api/preview", CorrelationSource.HEADER);
    }

    private record Run(List<Correlation> correlations, List<VerdictResult> verdicts) {
        VerdictResult only() {
            assertEquals(1, verdicts.size());
            return verdicts.get(0);
        }
    }

    private static Run run(List<AttackEvent> events, List<AlertEvent> alerts) {
        List<Correlation> correlations = new CorrelationEngine().correlate(events, alerts);
        return new Run(correlations, new VerdictEngine().judge(correlations));
    }

    private static long count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM validation." + table, Long.class);
    }

    // ---- P1 ----

    @Test
    void p1MigrationCreatesFiveTablesWithCheckConstraints() {
        List<String> tables = jdbc.queryForList("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'validation' AND table_name <> 'flyway_schema_history'
                  AND table_type = 'BASE TABLE'
                ORDER BY table_name""", String.class);
        assertEquals(List.of("benign_endpoint", "benign_request", "benign_result", "benign_unlinked_alert",
                        "correlation", "detection_link", "measurement_run", "metric_scope", "metric_snapshot",
                        "metric_snapshot_withdrawal", "nids_sid_class", "nids_window_stat", "run_provenance_note",
                        "telemetry_observation", "verdict_history", "verdict_member", "verdict_result"),
                // measurement_run: V2(S4-1), metric_scope: V3(S4-2), metric_snapshot·metric_snapshot_withdrawal: V5(S4-3),
                // nids_sid_class·nids_window_stat·telemetry_observation: V6(S4-4), benign_*: V7(S4-5), run_provenance_note: V11(S4-6)
                tables);

        List<String> checks = jdbc.queryForList("""
                SELECT con.conname FROM pg_constraint con
                JOIN pg_namespace ns ON ns.oid = con.connamespace
                WHERE ns.nspname = 'validation' AND con.contype = 'c'""", String.class);
        assertTrue(checks.containsAll(List.of(
                "ck_verdict_result_verdict", "ck_verdict_result_initial_verdict",
                "ck_verdict_result_detection_status", "ck_verdict_result_gt_outcome",
                "ck_verdict_result_attacker_verdict", "ck_verdict_result_unit_type",
                "ck_verdict_result_uncertain_reason", "ck_correlation_gt_outcome",
                "ck_correlation_attacker_verdict", "ck_verdict_history_from_verdict",
                "ck_verdict_history_to_verdict")), checks.toString());
    }

    // ---- P2 ----

    @Test
    void p2SingleCorrelationAndVerdictRoundTrip() {
        Run run = run(List.of(ssrfAttack()), List.of(ssrfAlert(700)));
        VerdictResult saved = run.only();

        repository.save(runId, run.correlations(), run.verdicts(), Map.of());

        assertEquals(saved, repository.findVerdict(saved.unitKey()).orElseThrow());
        Map<String, Object> row = jdbc.queryForMap("SELECT * FROM validation.correlation");
        assertEquals("rid-ssrf", row.get("correlation_key"));
        assertEquals("paw-1", row.get("paw"));
        assertEquals(null, row.get("op_id"));
        assertEquals(false, row.get("op_id_resolved"));
        assertEquals("SSRF", row.get("scenario"));
        assertEquals("DETECTED", row.get("detection_status_raw"));
        assertEquals(700L, row.get("mttd_ms_raw"));
        assertEquals("HEADER", row.get("correlation_source"));
        Map<String, Object> link = jdbc.queryForMap("SELECT * FROM validation.detection_link");
        assertEquals("100240", link.get("rule_id"));
        assertEquals("HEADER", link.get("match_path"));
        assertEquals(false, link.get("late"));
        assertEquals(VerdictEngine.ENGINE_VERSION,
                jdbc.queryForObject("SELECT engine_version FROM validation.verdict_result", String.class));
    }

    // ---- P3 ----

    @Test
    void p3SprayCampaignIsOneVerdictWithMemberRows() {
        List<AttackEvent> events = new ArrayList<>();
        List<AlertEvent> alerts = new ArrayList<>();
        for (int u = 0; u < 6; u++) {
            for (int i = 0; i < 2; i++) {
                String rid = "u" + u + "-" + i;
                long offset = u * 100L + i * 10;
                events.add(new AttackEvent(new CorrelationKey("paw-1", "7aa89a87", rid), "BRUTE_FORCE", "T1110",
                        T0.plusMillis(offset), IP, "/api/auth/login", "user" + u, GroundTruthOutcome.FAILED));
                alerts.add(new AlertEvent("100230", "T1110", T0.plusMillis(offset + 700), null, rid,
                        "paw-1", "7aa89a87", IP, "/api/auth/login", CorrelationSource.HEADER, "user" + u));
            }
        }
        Run run = run(events, alerts);
        assertEquals(UnitType.SPRAY_CAMPAIGN, run.only().unitType());

        repository.save(runId, run.correlations(), run.verdicts(), Map.of());

        assertEquals(1, count("verdict_result"));
        assertEquals(6, count("verdict_member"));
        assertEquals(6, count("correlation"));
        assertEquals("SPRAY_CAMPAIGN", jdbc.queryForObject("SELECT unit_type FROM validation.verdict_result", String.class));
    }

    // ---- P4 ----

    @Test
    void p4ResavingSameCorrelationKeyDoesNotDuplicate() {
        Run run = run(List.of(ssrfAttack()), List.of(ssrfAlert(700)));

        repository.save(runId, run.correlations(), run.verdicts(), Map.of());
        repository.save(runId, run.correlations(), run.verdicts(), Map.of());

        assertEquals(1, count("correlation"));
        assertEquals(1, count("detection_link"));
        assertEquals(1, count("verdict_result"));
        assertEquals(1, count("verdict_member"));
        assertEquals(0, count("verdict_history"));
    }

    // ---- P5 ----

    @Test
    void p5LateAlertChangesVerdictWithHistoryAndKeepsInitialVerdict() {
        Run first = run(List.of(ssrfAttack()), List.of());
        assertEquals(Verdict.SUCCEEDED_MISSED, first.only().verdict());
        repository.save(runId, first.correlations(), first.verdicts(), Map.of());

        Run later = run(List.of(ssrfAttack()), List.of(ssrfAlert(31_000)));
        assertEquals(Verdict.SUCCEEDED_DETECTED, later.only().verdict());
        repository.save(runId, later.correlations(), later.verdicts(), Map.of());

        assertEquals(1, count("verdict_result"));
        Map<String, Object> verdict = jdbc.queryForMap("SELECT verdict, initial_verdict, late_detection FROM validation.verdict_result");
        assertEquals("SUCCEEDED_DETECTED", verdict.get("verdict"));
        assertEquals("SUCCEEDED_MISSED", verdict.get("initial_verdict"));
        assertEquals(true, verdict.get("late_detection"));
        Map<String, Object> history = jdbc.queryForMap("SELECT from_verdict, to_verdict, reason FROM validation.verdict_history");
        assertEquals("SUCCEEDED_MISSED", history.get("from_verdict"));
        assertEquals("SUCCEEDED_DETECTED", history.get("to_verdict"));
        assertEquals("LATE_ALERT", history.get("reason"));
        assertEquals(true, jdbc.queryForObject("SELECT late FROM validation.detection_link", Boolean.class));
    }

    // ---- P6 ----

    @Test
    void p6CheckConstraintRejectsInvalidVerdict() {
        DataAccessException e = assertThrows(DataAccessException.class, () -> jdbc.update("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, verdict, initial_verdict, detection_status,
                    gt_outcome, overestimate, best_confidence, late_detection, spray_account_count, engine_version, run_id)
                VALUES ('bad', 'SINGLE', 'DETECTED', 'SUCCEEDED_MISSED', 'DETECTED', 'SUCCEEDED', false, 1.0, false, 0, 's3-v1', ?)
                """, runId));
        assertTrue(e.getMostSpecificCause().getMessage().contains("ck_verdict_result_verdict"),
                e.getMostSpecificCause().getMessage());
    }

    // ---- P7 ----

    @Test
    void p7VulnAppRoleCannotReadValidationSchema() {
        JdbcTemplate vulnApp = new JdbcTemplate(
                new DriverManagerDataSource(PG.getJdbcUrl(), VULN_APP_ROLE, VULN_APP_PASSWORD));

        DataAccessException e = assertThrows(DataAccessException.class,
                () -> vulnApp.queryForList("SELECT * FROM validation.verdict_result"));
        assertTrue(e.getMostSpecificCause().getMessage().contains("permission denied"),
                e.getMostSpecificCause().getMessage());
    }

    // ---- P8 ----

    private ApplicationContextRunner contextRunner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(DataSourceAutoConfiguration.class))
                .withUserConfiguration(ValidationPersistenceConfig.class)
                .withPropertyValues(
                        "spring.datasource.url=" + PG.getJdbcUrl(),
                        "spring.datasource.username=" + PG.getUsername(),
                        "spring.datasource.password=" + PG.getPassword());
    }

    @Test
    void p8PersistenceDisabledByDefaultCreatesNoValidationBeans() {
        contextRunner().run(ctx -> {
            assertFalse(ctx.containsBean("validationDataSource"));
            assertFalse(ctx.containsBean("verdictRepository"));
            assertTrue(ctx.containsBean("dataSource"));
        });
    }

    /** 켜도 취약 앱의 자동설정 DataSource 는 그대로 남는다 (validationDataSource 는 defaultCandidate=false) */
    @Test
    void p8PersistenceEnabledKeepsAppDataSource() {
        contextRunner()
                .withPropertyValues(
                        "app.validation.persistence.enabled=true",
                        "app.validation.datasource.url=" + PG.getJdbcUrl(),
                        "app.validation.datasource.username=validation_rw",
                        "app.validation.datasource.password=" + VALIDATION_PASSWORD)
                .run(ctx -> {
                    assertTrue(ctx.containsBean("validationDataSource"));
                    assertTrue(ctx.containsBean("verdictRepository"));
                    assertTrue(ctx.containsBean("dataSource"));
                });
    }
}
