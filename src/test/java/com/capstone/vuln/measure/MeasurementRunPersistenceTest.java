package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.AttemptRole;
import com.capstone.vuln.correlation.Correlation;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.OperationLink;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationSchemaMigrator;
import com.capstone.vuln.correlation.Verdict;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import com.capstone.vuln.correlation.VerdictResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S4-1 measurement_run(run 차원) + verdict_result.run_id/attempt_role (Testcontainers, PostgresTestImage)
 * T1 스키마 / T2 캠페인 1회 → run 귀속·CLOSED / T3 CLOSED run 신규 INSERT 차단 / T6 대조군 CONTROL / T7 R10
 */
@Testcontainers
class MeasurementRunPersistenceTest {

    @Container
    static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);

    private static final String VALIDATION_PASSWORD = UUID.randomUUID().toString();

    private static final String PAW = "mcukpa";
    private static final String SQLI = "e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c";
    private static final String SSRF = "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
    private static final String PT = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String BF = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";

    private static final long BASE = 1_000_000_000_000L;
    private static final Instant T0 = Instant.ofEpochMilli(BASE);
    private static final GitState CLEAN = new GitState("17a0b04deadbeef", false);
    /** runOnce 가 돌려주는 Caldera operation UUID */
    private static final String OP_UUID = "5b2c9e1a-7d3f-4e8a-9c6b-0a1b2c3d4e5f";
    private static final String OTHER_OP_UUID = "0f0e0d0c-0b0a-4908-8706-050403020100";

    private static DataSource ds;
    private static JdbcTemplate jdbc;
    private static VerdictRepository verdicts;
    private static MeasurementRunRepository runs;

    @TempDir
    Path reportDir;

    @BeforeAll
    static void bootstrap() throws Exception {
        psql("CREATE ROLE vulnapp LOGIN NOSUPERUSER PASSWORD '" + UUID.randomUUID() + "'");
        PG.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_role.sql"), "/tmp/validation_role.sql");
        ExecResult r = PG.execInContainer("psql", "-U", PG.getUsername(), "-d", PG.getDatabaseName(),
                "-v", "valpw=" + VALIDATION_PASSWORD, "-v", "app_role=vulnapp", "-f", "/tmp/validation_role.sql");
        assertEquals(0, r.getExitCode(), r.getStderr());

        ds = new DriverManagerDataSource(PG.getJdbcUrl(), "validation_rw", VALIDATION_PASSWORD);
        ValidationSchemaMigrator.migrate(ds);
        jdbc = new JdbcTemplate(ds);
        verdicts = new VerdictRepository(ds);
        runs = new MeasurementRunRepository(ds);
    }

    private static void psql(String sql) throws Exception {
        ExecResult r = PG.execInContainer("psql", "-v", "ON_ERROR_STOP=1",
                "-U", PG.getUsername(), "-d", PG.getDatabaseName(), "-c", sql);
        assertEquals(0, r.getExitCode(), r.getStderr());
    }

    @BeforeEach
    void clean() {
        // measurement_run 은 DELETE — TRUNCATE … CASCADE 는 FK 로 묶인 metric_snapshot(V5, TRUNCATE 거부)까지 닿는다
        jdbc.execute("TRUNCATE validation.verdict_history, validation.verdict_member, validation.verdict_result, "
                + "validation.detection_link, validation.correlation RESTART IDENTITY CASCADE");
        jdbc.update("DELETE FROM validation.measurement_run");
    }

    private static MeasurementRunRecorder recorder() {
        return new MeasurementRunRecorder(runs, () -> CLEAN, () -> RulesDigest.compute(Path.of(".")),
                AttemptManifest.ATTACK_VALIDATION_WEB, () -> BASE);
    }

    private static String errorOf(Runnable r) {
        DataAccessException e = assertThrows(DataAccessException.class, r::run);
        return e.getMostSpecificCause().getMessage();
    }

    // ---- T1 ----

    @Test
    void t1V2CreatesMeasurementRunAndUuidRunIdWithFkAndAttemptRoleCheck() {
        assertEquals(1, jdbc.queryForObject("""
                SELECT count(*) FROM information_schema.tables
                WHERE table_schema = 'validation' AND table_name = 'measurement_run'""", Integer.class));
        assertEquals("uuid", jdbc.queryForObject("""
                SELECT data_type FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'verdict_result' AND column_name = 'run_id'""",
                String.class));

        String fk = errorOf(() -> jdbc.update(insertVerdictSql("fk", "'ATTACK'"), UUID.randomUUID()));
        assertTrue(fk.contains("fk_verdict_result_run"), fk);

        UUID runId = recorder().open("t1", 1);
        String check = errorOf(() -> jdbc.update(insertVerdictSql("role", "'PROBE'"), runId));
        assertTrue(check.contains("ck_verdict_result_attempt_role"), check);

        // 기본값 ATTACK
        jdbc.update("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, verdict, initial_verdict, detection_status,
                    gt_outcome, overestimate, best_confidence, late_detection, spray_account_count, engine_version, run_id)
                VALUES ('dflt', 'SINGLE', 'SUCCEEDED_MISSED', 'SUCCEEDED_MISSED', 'NOT_DETECTED', 'SUCCEEDED',
                    false, 1.0, false, 0, 's3-v1', ?)""", runId);
        assertEquals("ATTACK", jdbc.queryForObject(
                "SELECT attempt_role FROM validation.verdict_result WHERE unit_key = 'dflt'", String.class));
    }

    private static String insertVerdictSql(String unitKey, String role) {
        return """
                INSERT INTO validation.verdict_result (unit_key, unit_type, verdict, initial_verdict, detection_status,
                    gt_outcome, overestimate, best_confidence, late_detection, spray_account_count, engine_version,
                    run_id, attempt_role)
                VALUES ('%s', 'SINGLE', 'SUCCEEDED_MISSED', 'SUCCEEDED_MISSED', 'NOT_DETECTED', 'SUCCEEDED',
                    false, 1.0, false, 0, 's3-v1', ?, %s)""".formatted(unitKey, role);
    }

    // ---- T2 + T6 + T7 (캠페인 1회, 가짜 Caldera·가짜 alert) ----

    private static final class FakeRunner extends OperationRunner {
        FakeRunner() {
            super(null, null, null, null, null, null, null, null, null);
        }

        @Override
        public RunResult runOnce(String name) {
            return new RunResult(OP_UUID, "finished", 60_000);
        }
    }

    private static String line(long offsetMs, String rid, String ability, String path, String outcome,
                               String tech, String args) {
        return ("{\"time\":%d,\"rid\":\"%s\",\"correlation\":{\"op_id\":\"" + PAW + "\",\"ability_id\":\"%s\","
                + "\"source\":\"HEADER\"},\"validation\":{\"outcome\":\"%s\",\"technique_id\":\"%s\"},"
                + "\"src_endpoint\":{\"ip\":\"172.20.0.1\"},\"http_request\":{\"url\":{\"path\":\"%s\"},\"args\":\"%s\"}}")
                .formatted(BASE + offsetMs, rid, ability, outcome, tech, path, args);
    }

    /** op 1회분 앱 로그: SQLi 1 / PT 3 / SSRF 메타 2 + 대조 1 / BF 실패 12 + 성공 1 */
    private static String opLog() {
        StringBuilder sb = new StringBuilder();
        sb.append(line(1_000, "sqli-1", SQLI, "/api/products/search", "SUCCEEDED", "T1190", "q=1'")).append('\n');
        for (int i = 1; i <= 3; i++) {
            sb.append(line(2_000 + i, "pt-" + i, PT, "/api/files/download", "SUCCEEDED", "T1190",
                    "filename=../../../../etc/passwd")).append('\n');
        }
        sb.append(line(3_000, "ssrf-md1", SSRF, "/api/preview", "SUCCEEDED", "T1190",
                "url=http://169.254.169.254/latest/meta-data/")).append('\n');
        sb.append(line(3_100, "ssrf-md2", SSRF, "/api/preview", "SUCCEEDED", "T1190",
                "url=http://169.254.169.254/latest/meta-data/")).append('\n');
        sb.append(line(3_200, "ssrf-ctl", SSRF, "/api/preview", "FAILED", "T1190", "url=http://example.com/")).append('\n');
        for (int i = 0; i < 12; i++) {
            sb.append(line(10_000 + i * 100L, "bf-f" + i, BF, "/api/auth/login", "FAILED", "T1110",
                    "username=user1")).append('\n');
        }
        sb.append(line(12_000, "bf-s", BF, "/api/auth/login", "SUCCEEDED", "T1110", "username=user1")).append('\n');
        return sb.toString();
    }

    /** 가짜 Caldera — 4개 ability 모두 [BASE, BASE+60s] 에 opId 링크 */
    private static OperationResolver caldera(String opId) {
        Instant finish = T0.plusSeconds(60);
        return new OperationResolver(() -> List.of(
                new OperationLink(opId, PAW, SQLI, T0, finish),
                new OperationLink(opId, PAW, SSRF, T0, finish),
                new OperationLink(opId, PAW, PT, T0, finish),
                new OperationLink(opId, PAW, BF, T0, finish)));
    }

    private MeasurementCampaign campaign(MeasurementRunRecorder recorder) {
        return campaign(recorder, caldera(OP_UUID));
    }

    private MeasurementCampaign campaign(MeasurementRunRecorder recorder, OperationResolver resolver) {
        MeasurementCollector collector = new MeasurementCollector(
                new GtLogReader(MeasurementRunPersistenceTest::opLog),
                new AlertIndexReader((from, to) -> "{\"hits\":{\"hits\":[]}}"),
                new AttackerVerdictResolver(id -> "{\"chain\":[]}"),
                Duration.ofSeconds(30));
        MeasurementHarness harness = new MeasurementHarness(collector, new CorrelationEngine(), new VerdictEngine(),
                verdicts, resolver);
        return new MeasurementCampaign(new FakeRunner(), harness, new GateVerdictReader(ds), recorder,
                new GateReportWriter(), Duration.ZERO, reportDir, () -> BASE, d -> { });
    }

    @Test
    void t2CampaignRecordsOneClosedRunAndAttributesEveryVerdict() {
        MeasurementRunRecorder recorder = recorder();
        campaign(recorder).run("t2", 1, false);

        Map<String, Object> run = jdbc.queryForMap("SELECT * FROM validation.measurement_run");
        UUID runId = (UUID) run.get("run_id");
        assertEquals("t2", run.get("label"));
        assertEquals("ATTACK", run.get("kind"));
        assertEquals("CLOSED", run.get("status"));
        assertNotNull(run.get("ended_at"));
        assertEquals("17a0b04deadbeef", run.get("git_commit"));
        assertEquals(false, run.get("git_dirty"));
        assertEquals(7, run.get("expected_attempts"));  // manifest 7 × op 1
        assertEquals(1, run.get("expected_controls"));  // manifest 1 × op 1
        assertTrue(run.get("rules_digest").toString().contains("caldera_abilities"));

        assertEquals(8, jdbc.queryForObject("SELECT count(*) FROM validation.verdict_result", Integer.class));
        assertEquals(List.of(runId), jdbc.queryForList(
                "SELECT DISTINCT run_id FROM validation.verdict_result", UUID.class), "전 verdict 같은 run_id");

        // T6 — SSRF 대조군 1건만 CONTROL
        assertEquals(List.of("unit:ssrf-ctl"), jdbc.queryForList(
                "SELECT unit_key FROM validation.verdict_result WHERE attempt_role = 'CONTROL'", String.class));

        // T7 — 실제 ATTACK 7·CONTROL 1 = expected → VALID
        assertEquals(new MeasurementRunRepository.RoleCounts(7, 1), runs.roleCounts(runId));
        assertEquals(SampleIntegrity.Status.VALID, recorder.integrity(runId).status());
    }

    @Test
    void t7RoleDistributionMismatchIsInvalid() {
        MeasurementRunRecorder recorder = recorder();
        campaign(recorder).run("t7", 1, false);
        UUID runId = jdbc.queryForObject("SELECT run_id FROM validation.measurement_run", UUID.class);

        // 대조군이 공격으로 집계된 상태(S3 방식) — 합계 8 은 같아도 INVALID (우선순위상 ATTACK_MISMATCH)
        jdbc.update("UPDATE validation.verdict_result SET attempt_role = 'ATTACK'");
        SampleIntegrity.Result r = recorder.integrity(runId);
        assertEquals(SampleIntegrity.Status.INVALID, r.status());
        assertEquals("ATTACK_MISMATCH (expected attack=7 control=1, actual attack=8 control=0)", r.reason());
    }

    @Test
    void newRunRequiresKnownGitDirtyFlag() {
        MeasurementRun unknownDirty = new MeasurementRun(UUID.randomUUID(), "x", MeasurementRun.Kind.ATTACK,
                MeasurementRun.Status.OPEN, T0, null, "abc", null, "{}", 1, 0, null);
        assertThrows(IllegalArgumentException.class, () -> runs.open(unknownDirty));
    }

    // ---- S4-1b op_id (Gap #6) ----

    private List<Map<String, Object>> runCorrelations() {
        return jdbc.queryForList("""
                SELECT DISTINCT c.correlation_key, c.op_id, c.op_id_resolved
                FROM validation.verdict_result v
                JOIN validation.verdict_member m ON m.verdict_id = v.id
                JOIN validation.correlation c ON c.id = m.correlation_id""");
    }

    @Test
    void opIdIsRecordedWhenCalderaLinkAgreesWithRunOnce() {
        campaign(recorder()).run("op-agree", 1, false);

        List<Map<String, Object>> rows = runCorrelations();
        assertEquals(8, rows.size()); // SQLi 1 + PT 3 + SSRF 3 + BF 1(13 이벤트가 Correlation 1개)
        for (Map<String, Object> row : rows) {
            assertEquals(UUID.fromString(OP_UUID), row.get("op_id"), row.toString());
            assertEquals(true, row.get("op_id_resolved"), row.toString());
        }
    }

    @Test
    void opIdStaysNullWhenCalderaLinkDisagreesWithRunOnce() {
        campaign(recorder(), caldera(OTHER_OP_UUID)).run("op-mismatch", 1, false);

        List<Map<String, Object>> rows = runCorrelations();
        assertEquals(8, rows.size());
        for (Map<String, Object> row : rows) {
            assertEquals(null, row.get("op_id"), row.toString());
            assertEquals(false, row.get("op_id_resolved"), row.toString());
        }
        assertEquals(8, rows("verdict_result"), "판정 단위 수 불변");
    }

    // ---- S4-1a truncate 보호 ----

    private static int rows(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM validation." + table, Integer.class);
    }

    @Test
    void truncateIsRefusedWhenAClosedRunExistsAndNothingIsDeleted() {
        campaign(recorder()).run("baseline", 1, false); // CLOSED run 1 + verdict 8
        int verdictRows = rows("verdict_result");
        int memberRows = rows("verdict_member");
        int correlationRows = rows("correlation");

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> campaign(recorder()).run("again", 1, true));
        assertTrue(e.getMessage().contains("CLOSED"), e.getMessage());

        assertEquals(verdictRows, rows("verdict_result"));
        assertEquals(memberRows, rows("verdict_member"));
        assertEquals(correlationRows, rows("correlation"));
        assertEquals(1, rows("measurement_run"), "새 run 도 열지 않는다");
    }

    @Test
    void truncateWithoutClosedRunKeepsPreviousBehavior() {
        save(recorder().open("legacy-open", 1), List.of(ssrf("rid-old")), List.of()); // OPEN run 의 이전 verdict
        assertEquals(1, rows("verdict_result"));

        campaign(recorder()).run("fresh", 1, true);

        assertEquals(0, jdbc.queryForObject(
                "SELECT count(*) FROM validation.verdict_result WHERE unit_key = 'unit:rid-old'", Integer.class));
        assertEquals(8, rows("verdict_result"));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM validation.measurement_run WHERE label = 'fresh' AND status = 'CLOSED'", Integer.class));
    }

    // ---- T3 ----

    private static AttackEvent ssrf(String rid) {
        return new AttackEvent(new CorrelationKey(PAW, SSRF, rid), "SSRF", "T1190",
                T0, "172.20.0.1", "/api/preview", null, GroundTruthOutcome.SUCCEEDED);
    }

    private static AlertEvent ssrfAlert(long offsetMs) {
        return new AlertEvent("100240", "T1190", T0.plusMillis(offsetMs), null,
                null, PAW, SSRF, "172.20.0.1", "/api/preview", CorrelationSource.HEADER);
    }

    private static void save(UUID runId, List<AttackEvent> events, List<AlertEvent> alerts) {
        List<Correlation> correlations = new CorrelationEngine().correlate(events, alerts);
        List<VerdictResult> results = new VerdictEngine().judge(correlations);
        verdicts.save(runId, correlations, results, Map.of());
    }

    @Test
    void t3ClosedRunRejectsNewVerdictButAllowsLateAlertUpdate() {
        MeasurementRunRecorder recorder = recorder();
        UUID runId = recorder.open("t3", 1);
        save(runId, List.of(ssrf("rid-a")), List.of());
        recorder.close(runId);

        // 늦은 alert 로 기존 verdict 갱신(UPDATE) — 허용, run_id 유지
        save(runId, List.of(ssrf("rid-a")), List.of(ssrfAlert(31_000)));
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT verdict, run_id FROM validation.verdict_result WHERE unit_key = 'unit:rid-a'");
        assertEquals(Verdict.SUCCEEDED_DETECTED.name(), row.get("verdict"));
        assertEquals(runId, row.get("run_id"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM validation.verdict_history", Integer.class));

        // CLOSED run 에 새 verdict INSERT — 거부
        String msg = errorOf(() -> save(runId, List.of(ssrf("rid-b")), List.of()));
        assertTrue(msg.contains("CLOSED"), msg);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM validation.verdict_result", Integer.class));
    }

    @Test
    void closeIsOnlyFromOpen() {
        MeasurementRunRecorder recorder = recorder();
        UUID runId = recorder.open("once", 1);
        recorder.close(runId);
        assertThrows(IllegalStateException.class, () -> recorder.close(runId));
    }

    @Test
    void roleMapIsStoredOnInsert() {
        UUID runId = recorder().open("roles", 1);
        List<Correlation> correlations = new CorrelationEngine().correlate(List.of(ssrf("rid-c")), List.of());
        List<VerdictResult> results = new VerdictEngine().judge(correlations);
        verdicts.save(runId, correlations, results, Map.of("unit:rid-c", AttemptRole.CONTROL));
        assertEquals("CONTROL", jdbc.queryForObject("SELECT attempt_role FROM validation.verdict_result", String.class));
    }
}
