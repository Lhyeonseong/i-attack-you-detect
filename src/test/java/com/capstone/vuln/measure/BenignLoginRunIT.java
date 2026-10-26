package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S4-5-BENIGN-LOGIN 외부 전송 run 진입점 (ADR-S4-01 v2.0 R17 f·R18 j) — RUN_BENIGN_LOGIN=1 일 때만 실행, 기본 build 에서 돌지 않는다.
 * 전송은 코드가 하지 않는다 — 사람이 터미널 스크립트로 보내 결과 CSV(seq,sent_at_ms,responded_at_ms,status)를 만들고,
 * 이 진입점은 open(run 생성) 과 ingest(결과 CSV 적재) 두 모드로만 동작한다. 실행 절차: detections/measurements/RUNBOOK-S4-5-benign.md (3-L).
 *
 * <p>env: BENIGN_LOGIN_MODE(open|ingest), LOGIN_PLAN_FILE(login-plan CSV), POSTGRES_DB, VALIDATION_DB_PASSWORD,
 * open: BENIGN_LABEL. ingest: BENIGN_LOGIN_RUN_ID(open 이 출력한 run_id), RESULT_CSV, INDEXER_CA_FILE·INDEXER_USERNAME·INDEXER_PASSWORD.
 * 가드(스키마 버전 하드코딩 대신 동적): benign_endpoint 에 login 행이 있어야 한다(V9 이후). open 은 git 작업 트리 깨끗·같은 label 없음도 본다.
 */
@EnabledIfEnvironmentVariable(named = "RUN_BENIGN_LOGIN", matches = "1")
class BenignLoginRunIT {

    private static final Duration OBSERVATION = Duration.ofSeconds(30);

    private static String env(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(name + " 필요 (기본값 없음)");
        }
        return v.strip();
    }

    @Test
    void run() throws Exception {
        String mode = env("BENIGN_LOGIN_MODE");
        LoginPlan plan = LoginPlan.load(Path.of(env("LOGIN_PLAN_FILE")));
        DataSource ds = new DriverManagerDataSource(
                "jdbc:postgresql://127.0.0.1:5433/" + env("POSTGRES_DB") + "?currentSchema=validation",
                "validation_rw", env("VALIDATION_DB_PASSWORD"));
        JdbcTemplate jdbc = new JdbcTemplate(ds);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM validation.benign_endpoint WHERE endpoint = ?",
                Integer.class, LoginPlan.ENDPOINT), "benign_endpoint 에 login 행이 없다 — V9 먼저 (RUNBOOK 1-V9)");

        MeasurementRunRepository runs = new MeasurementRunRepository(ds);

        if ("open".equals(mode)) {
            String label = env("BENIGN_LABEL");
            assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM validation.measurement_run WHERE label = ?",
                    Integer.class, label), "같은 label run 이 이미 있다");
            GitState git = GitStateSource.cli(Path.of(".")).read();
            assertFalse(git.dirty(), "git 작업 트리가 깨끗하지 않다 — git_dirty=f 로 측정한다(측정 로그는 /tmp 에)");
            RulesDigest digest = RulesDigest.compute(Path.of("."));
            ExternalSendIngest ext = new ExternalSendIngest(ds, runs, null);
            UUID runId = ext.open(expected -> MeasurementRun.open(label, MeasurementRun.Kind.BENIGN, Instant.now(),
                    git, digest, expected, 0), plan, LoginPlan.ENDPOINT);
            System.out.println("BENIGN>> login run_id=" + runId);
            return;
        }

        if ("ingest".equals(mode)) {
            UUID runId = UUID.fromString(env("BENIGN_LOGIN_RUN_ID"));
            Path resultCsv = Path.of(env("RESULT_CSV"));
            assertTrue(Files.isReadable(resultCsv), "RESULT_CSV 를 읽을 수 없다: " + resultCsv);
            Path ca = Path.of(env("INDEXER_CA_FILE"));
            assertTrue(Files.isReadable(ca), "INDEXER_CA_FILE 을 읽을 수 없다: " + ca);
            String indexer = "https://127.0.0.1:9200";
            String user = env("INDEXER_USERNAME");
            String pass = env("INDEXER_PASSWORD");
            BenignAlertReader alerts = new BenignAlertReader(
                    new IndexerAlertSearchSource(indexer, "wazuh-alerts-*", user, pass, "vuln-webapp", ca),
                    IndexerAlertSearchSource.forRuleId(indexer, "wazuh-alerts-*", user, pass, "86601", ca),
                    Duration.ofSeconds(60));
            BenignIngest pipeline = new BenignIngest(runs,
                    new BenignLogReader(new DockerExecAttackLogSource(
                            "docker/docker-compose.yml", "security-lab", "target-web", "/var/log/target/attack.json.log")),
                    alerts, new BenignAlertLinker(NidsSidCatalog.V1_7, OBSERVATION), new BenignRunRepository(ds),
                    OBSERVATION, System::currentTimeMillis);
            new ExternalSendIngest(ds, runs, pipeline).ingest(runId, plan, resultCsv);
            Map<String, Object> r10 = jdbc.queryForMap("SELECT r10_status, r10_reason, expected_attempts, benign_loaded, "
                    + "benign_matched FROM validation.v_run_integrity WHERE run_id = ?", runId);
            System.out.println("BENIGN>> login run_id=" + runId + " R10=" + r10);
            return;
        }

        throw new IllegalStateException("BENIGN_LOGIN_MODE 는 open|ingest: " + mode);
    }
}
