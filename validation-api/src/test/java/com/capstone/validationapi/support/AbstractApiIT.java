package com.capstone.validationapi.support;

import org.flywaydb.core.Flyway;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import java.util.UUID;

/**
 * validation-api 통합 테스트 베이스: 운영과 같은 postgres digest 컨테이너에 role 부트스트랩 → V1~V12 migrate →
 * VALID run 2개(개선 전/후) 시드 + take_metric_snapshot. 앱은 validation_ro 로 접속(읽기 전용 경계 포함).
 * MockMvc(MOCK 환경) — 실제 TLS 핸드셰이크는 스모크(Step5)에서, 여기선 필터체인·계약·일관성 검증.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
public abstract class AbstractApiIT {

    // 운영 compose·PostgresTestImage 와 같은 digest(ADR-S4-03 D1 = postgres:16.15-trixie)
    private static final String PG_IMAGE =
            "postgres@sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d";

    public static final String BEARER = "s46-test-bearer-token-0123456789abcd";
    public static final String UI_USER = "viewer";
    public static final String UI_PASSWORD = "viewerpass-0123";
    // 고정 run id(라벨만 실데이터와 유사, 값은 테스트 전용)
    public static final UUID AFTER = UUID.fromString("805f3b8e-0000-0000-0000-000000000001");
    public static final UUID BEFORE = UUID.fromString("b1c26be1-0000-0000-0000-000000000002");
    public static final UUID INVALID_RUN = UUID.fromString("dffb77a7-0000-0000-0000-000000000003");

    protected static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PG_IMAGE);
    private static String roPw;
    private static String[] tls;

    static {
        tls = TestTls.writeTempCertAndKey();
        PG.start();
        bootstrapMigrateSeed();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", PG::getJdbcUrl);
        r.add("spring.datasource.username", () -> "validation_ro");
        r.add("spring.datasource.password", () -> roPw);
        r.add("spring.ssl.bundle.pem.validationapi.keystore.certificate", () -> tls[0]);
        r.add("spring.ssl.bundle.pem.validationapi.keystore.private-key", () -> tls[1]);
        r.add("server.ssl.enabled", () -> "false");    // MOCK: 커넥터 없음(번들은 로드만)
        r.add("validationapi.bearer-tokens", () -> BEARER);
        r.add("validationapi.ui.username", () -> UI_USER);
        r.add("validationapi.ui.password-bcrypt", () -> new BCryptPasswordEncoder().encode(UI_PASSWORD));
    }

    private static void bootstrapMigrateSeed() {
        String su = PG.getUsername();
        String db = PG.getDatabaseName();
        String rwPw = UUID.randomUUID().toString();
        roPw = UUID.randomUUID().toString();
        try {
            exec("psql", "-v", "ON_ERROR_STOP=1", "-U", su, "-d", db, "-c", "CREATE ROLE vulnapp LOGIN NOSUPERUSER");
            PG.copyFileToContainer(MountableFile.forHostPath("../db/bootstrap/validation_role.sql"),
                    "/tmp/validation_role.sql");
            exec("psql", "-v", "ON_ERROR_STOP=1", "-U", su, "-d", db,
                    "-v", "valpw=" + rwPw, "-v", "app_role=vulnapp", "-f", "/tmp/validation_role.sql");
            PG.copyFileToContainer(MountableFile.forHostPath("../db/bootstrap/validation_ro_role.sql"),
                    "/tmp/validation_ro_role.sql");
            exec("psql", "-v", "ON_ERROR_STOP=1", "-U", su, "-d", db,
                    "-v", "ropw=" + roPw, "-v", "dbname=" + db, "-f", "/tmp/validation_ro_role.sql");
        } catch (Exception e) {
            throw new IllegalStateException("role 부트스트랩 실패", e);
        }

        DriverManagerDataSource rwDs = new DriverManagerDataSource(PG.getJdbcUrl(), "validation_rw", rwPw);
        Flyway.configure().dataSource(rwDs).schemas("validation").defaultSchema("validation")
                .createSchemas(false).locations("filesystem:../src/main/resources/db/validation")
                .load().migrate();

        seed(new JdbcTemplate(rwDs));
    }

    /** 개선 전/후 VALID run 2개(공격 140 + 대조 20)를 시드하고 스냅샷을 만든다. */
    private static void seed(JdbcTemplate jdbc) {
        createRun(jdbc, BEFORE, "S4-STACK-6-BASELINE", "e3b5f52");
        createRun(jdbc, AFTER, "S5-SQLI-AFTER", "2abc879");
        // 비-VALID run(지표 409 테스트용): 기대치만 있고 시도 미적재 → 카운트 불일치 → INVALID
        jdbc.update("""
                INSERT INTO validation.measurement_run(run_id,label,kind,status,started_at,ended_at,git_commit,
                    git_dirty,rules_digest,expected_attempts,expected_controls)
                VALUES (?, 'INVALID-RUN', 'ATTACK', 'CLOSED', now()-interval '1 hour', now(), 'deadbee',
                    false, '{}'::jsonb, 140, 20)""", INVALID_RUN);

        // 개선 후: 전부 탐지
        attack(jdbc, AFTER, "SQLI", "T1190", 20, true, "s4-v1");
        attack(jdbc, AFTER, "PATH_TRAVERSAL", "T1190", 60, true, "s4-v1");
        attack(jdbc, AFTER, "SSRF", "T1190", 40, true, "s4-v1");
        attack(jdbc, AFTER, "BRUTE_FORCE", "T1110", 20, true, "s4-v1");
        control(jdbc, AFTER, 20, "s4-v1");
        // 개선 전: SQLI 20 놓침(나머지 동일)
        attack(jdbc, BEFORE, "SQLI", "T1190", 20, false, "s3-v1");
        attack(jdbc, BEFORE, "PATH_TRAVERSAL", "T1190", 60, true, "s3-v1");
        attack(jdbc, BEFORE, "SSRF", "T1190", 40, true, "s3-v1");
        attack(jdbc, BEFORE, "BRUTE_FORCE", "T1110", 20, true, "s3-v1");
        control(jdbc, BEFORE, 20, "s3-v1");

        // 적재 완료 → CLOSED 전환(ck_measurement_run_closed_has_end: ended_at 동반). 그래야 VALID·스냅샷 가능.
        jdbc.update("UPDATE validation.measurement_run SET status='CLOSED', ended_at=now() WHERE run_id IN (?,?)",
                AFTER, BEFORE);

        jdbc.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, AFTER);
        jdbc.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, BEFORE);
    }

    // OPEN 으로 생성(verdict INSERT 허용). 적재 후 closeRuns()가 CLOSED 로 전환(VALID 전제).
    private static void createRun(JdbcTemplate jdbc, UUID id, String label, String commit) {
        jdbc.update("""
                INSERT INTO validation.measurement_run(run_id,label,kind,status,started_at,ended_at,git_commit,
                    git_dirty,rules_digest,expected_attempts,expected_controls)
                VALUES (?,?, 'ATTACK', 'OPEN', now()-interval '1 hour', NULL, ?, false, '{}'::jsonb, 140, 20)""",
                id, label, commit);
    }

    /** detected=true → SUCCEEDED_DETECTED/DETECTED, false → SUCCEEDED_MISSED/NOT_DETECTED. */
    private static void attack(JdbcTemplate jdbc, UUID run, String scenario, String tech, int count,
                               boolean detected, String engine) {
        String verdict = detected ? "SUCCEEDED_DETECTED" : "SUCCEEDED_MISSED";
        String det = detected ? "DETECTED" : "NOT_DETECTED";
        String mttd = detected ? "(500 + g*5)::bigint" : "NULL::bigint";
        double conf = detected ? 0.9 : 0.0;
        jdbc.update("INSERT INTO validation.verdict_result("
                + "unit_key,unit_type,scenario,technique_id,verdict,initial_verdict,detection_status,gt_outcome,"
                + "attacker_verdict,attacker_match,overestimate,best_confidence,mttd_ms,late_detection,"
                + "spray_account_count,engine_version,run_id,attempt_role) "
                + "SELECT ?||'-'||g, 'SINGLE', ?, ?, ?, ?, ?, 'SUCCEEDED', 'SUCCEEDED', true, false, ?, "
                + mttd + ", false, 0, ?, ?, 'ATTACK' FROM generate_series(1,?) g",
                "u:" + run + ":" + scenario, scenario, tech, verdict, verdict, det, conf, engine, run, count);
    }

    private static void control(JdbcTemplate jdbc, UUID run, int count, String engine) {
        jdbc.update("INSERT INTO validation.verdict_result("
                + "unit_key,unit_type,scenario,technique_id,verdict,initial_verdict,detection_status,gt_outcome,"
                + "attacker_verdict,attacker_match,overestimate,best_confidence,mttd_ms,late_detection,"
                + "spray_account_count,engine_version,run_id,attempt_role) "
                + "SELECT ?||'-'||g, 'SINGLE', 'SSRF', 'T1190', 'FAILED_UNSEEN', 'FAILED_UNSEEN', 'NOT_DETECTED', "
                + "'FAILED', 'FAILED', true, false, 0.0, NULL::bigint, false, 0, ?, ?, 'CONTROL' "
                + "FROM generate_series(1,?) g",
                "c:" + run + ":ssrf", engine, run, count);
    }

    private static void exec(String... cmd) throws Exception {
        var r = PG.execInContainer(cmd);
        if (r.getExitCode() != 0) {
            throw new IllegalStateException("exec 실패: " + String.join(" ", cmd) + "\n" + r.getStderr());
        }
    }
}
