package com.capstone.vuln.correlation;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * S4-6 — validation_ro 읽기 전용 role 권한 경계 (ADR-S4-02 D2·D3·D11).
 *
 * <p>전용 컨테이너를 쓴다: 공유 {@link ValidationDbFixture#PG} 는 validation_ro 없이 이미 migrate 되어
 * V12 GRANT 가 건너뛰어진 상태이기 때문. 여기서는 role 생성 → migrate(V1→V12) 순서로 GRANT 를 실제 적용한다.
 *
 * <p>ADR-S4-02 D2 핵심: default_transaction_read_only 는 보조 장치이고 실제 경계는 "쓰기 권한 없음".
 * 따라서 쓰기 거부 테스트는 세션에서 read-only 를 끈 뒤 permission denied(42501)를 확인한다.
 */
@Testcontainers
class ValidationRoRoleTest {

    private static final String SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501";

    /** V12 가 validation_ro 에 SELECT 를 주는 관계 — 이 집합이 전부여야 한다(초과·누락 모두 실패). */
    private static final Set<String> EXPECTED_SELECT = Set.of(
            "v_metric_rates", "v_metric_mttd", "v_metric_correlation", "v_metric_h2",
            "v_metric_coverage", "v_metric_attacker", "v_metric_m07a", "v_metric_m13",
            "v_metric_m14a", "v_metric_m14b", "v_metric_m14_rule", "v_run_integrity",
            "v_api_attempt", "v_api_alert_link", "v_benign_final_result",
            "measurement_run", "metric_snapshot", "metric_snapshot_withdrawal", "run_provenance_note");

    /** EXECUTE 는 PUBLIC 회수된 통계 함수 3개뿐(compare_snapshots·스냅샷/트리거 함수는 없음). */
    private static final Set<String> EXPECTED_EXECUTE = Set.of(
            "wilson_ci", "quantile_t8", "newcombe_diff_ci");

    private static PostgreSQLContainer<?> pg;
    private static JdbcTemplate rw;     // validation_rw
    private static DataSource roDs;     // validation_ro

    @BeforeAll
    static void setUp() throws Exception {
        pg = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
        pg.start();

        // 취약 앱 role + validation_rw(+schema) — 운영 부트스트랩과 같은 경로
        check(pg.execInContainer("psql", "-v", "ON_ERROR_STOP=1", "-U", pg.getUsername(),
                "-d", pg.getDatabaseName(), "-c", "CREATE ROLE vulnapp LOGIN NOSUPERUSER"));
        pg.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_role.sql"),
                "/tmp/validation_role.sql");
        String rwPw = UUID.randomUUID().toString();
        check(pg.execInContainer("psql", "-U", pg.getUsername(), "-d", pg.getDatabaseName(),
                "-v", "valpw=" + rwPw, "-v", "app_role=vulnapp", "-f", "/tmp/validation_role.sql"));

        // validation_ro — migrate 전에 만들어 V12 GRANT 가 실제 적용되게 한다
        pg.copyFileToContainer(MountableFile.forHostPath("db/bootstrap/validation_ro_role.sql"),
                "/tmp/validation_ro_role.sql");
        String roPw = UUID.randomUUID().toString();
        check(pg.execInContainer("psql", "-U", pg.getUsername(), "-d", pg.getDatabaseName(),
                "-v", "ropw=" + roPw, "-v", "dbname=" + pg.getDatabaseName(), "-f", "/tmp/validation_ro_role.sql"));

        DataSource rwDs = new DriverManagerDataSource(pg.getJdbcUrl(), "validation_rw", rwPw);
        ValidationSchemaMigrator.migrate(rwDs);
        rw = new JdbcTemplate(rwDs);
        roDs = new DriverManagerDataSource(pg.getJdbcUrl(), "validation_ro", roPw);
    }

    @AfterAll
    static void tearDown() {
        if (pg != null) {
            pg.stop();
        }
    }

    // ── 1. 권한 허용 목록 (초과·누락 모두 실패) ────────────────────────────────
    @Test
    void grantAllowListIsExact() {
        // SELECT 대상 집합 == 기대 집합
        List<String> selectRows = rw.query(
                "SELECT table_name FROM information_schema.role_table_grants "
                        + "WHERE grantee='validation_ro' AND table_schema='validation'",
                (r, i) -> r.getString(1));
        assertEquals(new TreeSet<>(EXPECTED_SELECT), new TreeSet<>(selectRows),
                "validation_ro SELECT 허용 목록이 기대와 다름(초과 또는 누락)");

        // SELECT 외 권한(INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER)은 하나도 없어야 함
        List<String> nonSelect = rw.query(
                "SELECT table_name||':'||privilege_type FROM information_schema.role_table_grants "
                        + "WHERE grantee='validation_ro' AND table_schema='validation' AND privilege_type <> 'SELECT'",
                (r, i) -> r.getString(1));
        assertTrue(nonSelect.isEmpty(), "validation_ro 에 SELECT 외 권한 존재: " + nonSelect);

        // EXECUTE 함수 집합 == 기대(통계 3개)
        List<String> execRows = rw.query(
                "SELECT routine_name FROM information_schema.role_routine_grants "
                        + "WHERE grantee='validation_ro' AND specific_schema='validation' AND privilege_type='EXECUTE'",
                (r, i) -> r.getString(1));
        assertEquals(new TreeSet<>(EXPECTED_EXECUTE), new TreeSet<>(execRows),
                "validation_ro EXECUTE 허용 목록이 기대와 다름");

        // 스키마는 USAGE 만(CREATE 없음)
        assertTrue(Boolean.TRUE.equals(rw.queryForObject(
                "SELECT has_schema_privilege('validation_ro','validation','USAGE')", Boolean.class)),
                "스키마 USAGE 없음");
        assertFalse(Boolean.TRUE.equals(rw.queryForObject(
                "SELECT has_schema_privilege('validation_ro','validation','CREATE')", Boolean.class)),
                "스키마 CREATE 가 있으면 안 됨");
    }

    // ── 2. 허용된 뷰/함수는 읽힌다 ────────────────────────────────────────────
    @Test
    void allowedReadsWork() {
        for (String rel : EXPECTED_SELECT) {
            runOk(roDs, "SELECT count(*) FROM validation." + rel);
        }
        runOk(roDs, "SELECT * FROM validation.wilson_ci(10, 20)");
        runOk(roDs, "SELECT * FROM validation.newcombe_diff_ci(0, 20, 20, 20)");
    }

    // ── 3. 기반 테이블 SELECT 거부 ────────────────────────────────────────────
    @Test
    void baseTableSelectDenied() {
        for (String base : List.of("verdict_result", "verdict_member", "correlation",
                "detection_link", "verdict_history", "metric_scope")) {
            assertDenied(roDs, "SELECT * FROM validation." + base + " LIMIT 1");
        }
    }

    // ── 4. 쓰기 거부(read-only 끈 뒤에도 permission denied) ────────────────────
    @Test
    void writesDeniedEvenWithReadOnlyOff() {
        // 스냅샷 적재 테이블
        assertDenied(roDs, "INSERT INTO validation.metric_snapshot(run_id, metric_id) "
                + "VALUES (gen_random_uuid(), 'X')");
        assertDenied(roDs, "UPDATE validation.metric_snapshot SET status='X'");
        assertDenied(roDs, "DELETE FROM validation.metric_snapshot");
        assertDenied(roDs, "TRUNCATE validation.metric_snapshot");
        // measurement_run 불변(ro 입장): 쓰기 전부 거부
        assertDenied(roDs, "INSERT INTO validation.measurement_run(run_id,label,kind,status,started_at,git_commit,rules_digest) "
                + "VALUES (gen_random_uuid(),'x','ATTACK','OPEN',now(),'x','{}'::jsonb)");
        assertDenied(roDs, "UPDATE validation.measurement_run SET label='x'");
        assertDenied(roDs, "DELETE FROM validation.measurement_run");
        // 출처 표도 ro 는 INSERT 불가(SELECT 만 허용)
        assertDenied(roDs, "INSERT INTO validation.run_provenance_note(run_id,item,value,source_file) "
                + "VALUES (gen_random_uuid(),'x','x','x')");
    }

    // ── 5. 트리거 함수·스냅샷 함수 EXECUTE 없음 ───────────────────────────────
    @Test
    void forbiddenFunctionsNotExecutable() {
        for (String fn : List.of(
                "has_function_privilege('validation_ro','validation.take_metric_snapshot(uuid)','EXECUTE')",
                "has_function_privilege('validation_ro','validation.compare_snapshots(uuid,uuid)','EXECUTE')",
                "has_function_privilege('validation_ro','validation.run_provenance_note_reject_change()','EXECUTE')")) {
            assertFalse(Boolean.TRUE.equals(rw.queryForObject("SELECT " + fn, Boolean.class)),
                    "금지 함수 EXECUTE 가 있으면 안 됨: " + fn);
        }
    }

    // ── 6. run_provenance_note append-only: validation_rw(소유자)도 UPDATE/DELETE 거부 ──
    @Test
    void provenanceNoteIsAppendOnly() {
        UUID runId = UUID.randomUUID();
        rw.update("INSERT INTO validation.measurement_run(run_id,label,kind,status,started_at,git_commit,git_dirty,rules_digest) "
                + "VALUES (?,?,?,?,now(),?,false,'{}'::jsonb)",
                runId, "RO-TEST", "ATTACK", "OPEN", "test");
        rw.update("INSERT INTO validation.run_provenance_note(run_id,item,value,source_file,source_line) "
                + "VALUES (?,?,?,?,?)", runId, "wazuh", "4.14.9", "evidence/x.log", 1);

        assertDaoDenied(() -> rw.update("UPDATE validation.run_provenance_note SET value='9.9.9' WHERE run_id=?", runId),
                "run_provenance_note UPDATE 는 거부되어야 함");
        assertDaoDenied(() -> rw.update("DELETE FROM validation.run_provenance_note WHERE run_id=?", runId),
                "run_provenance_note DELETE 는 거부되어야 함");
        assertDaoDenied(() -> rw.execute("TRUNCATE validation.run_provenance_note"),
                "run_provenance_note TRUNCATE 는 거부되어야 함");
        // INSERT(append)는 소유자에게 허용 — 유지 확인
        assertEquals(1, rw.queryForObject(
                "SELECT count(*) FROM validation.run_provenance_note WHERE run_id=?", Integer.class, runId));
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    private static void runOk(DataSource ds, String sql) {
        try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
            s.execute(sql);
        } catch (SQLException e) {
            fail("허용되어야 할 읽기가 실패: " + sql + " → " + e.getSQLState() + " " + e.getMessage());
        }
    }

    private static void assertDenied(DataSource ds, String sql) {
        try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
            s.execute("SET default_transaction_read_only = off"); // 실제 경계는 권한(ADR D2)
            s.execute(sql);
            fail("거부되어야 할 쿼리가 성공: " + sql);
        } catch (SQLException e) {
            assertEquals(SQLSTATE_INSUFFICIENT_PRIVILEGE, e.getSQLState(),
                    "permission denied(42501) 아님: " + sql + " → " + e.getSQLState() + " " + e.getMessage());
        }
    }

    private static void assertDaoDenied(Runnable r, String msg) {
        try {
            r.run();
            fail(msg);
        } catch (org.springframework.dao.DataAccessException e) {
            SQLException sql = findSqlException(e);
            assertTrue(sql != null && SQLSTATE_INSUFFICIENT_PRIVILEGE.equals(sql.getSQLState()),
                    msg + " (실제 SQLState=" + (sql == null ? "?" : sql.getSQLState()) + ")");
        }
    }

    private static SQLException findSqlException(Throwable t) {
        while (t != null && !(t instanceof SQLException)) {
            t = t.getCause();
        }
        return (SQLException) t;
    }

    private static void check(ExecResult r) {
        if (r.getExitCode() != 0) {
            throw new IllegalStateException("psql 부트스트랩 실패: " + r.getStderr());
        }
    }
}
