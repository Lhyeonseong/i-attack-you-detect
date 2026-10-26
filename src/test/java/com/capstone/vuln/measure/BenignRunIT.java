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
 * S4-5-BENIGN-WEB 측정 진입점 (ADR-S4-01 v1.8 R17·R18) — RUN_BENIGN_MEASURE=1 일 때만 실행, 기본 build 에서는 돌지 않는다.
 * 순서·실패 시 남는 것은 {@link BenignWebRun}. 스냅샷은 찍지 않는다(RUNBOOK (4) 에서 사람이 확인 후).
 *
 * <p>run 을 열기 전 가드(하나라도 어긋나면 아무것도 보내지 않고 실패): V7 스키마(이 진입점은 migrate 하지 않는다), 같은 label run 없음,
 * git 작업 트리 깨끗(git_dirty = false), 인덱서 루트 CA 파일 읽기 가능, 인덱서 두 질의 사전 시험.
 * 실행 절차: detections/measurements/RUNBOOK-S4-5-benign.md
 *
 * <p>env: BENIGN_LABEL(필수, 기본값 없음), INDEXER_CA_FILE(필수 — 인덱서 루트 CA PEM, 체인 검증 + 호스트명만 생략),
 * POSTGRES_DB, VALIDATION_DB_PASSWORD, INDEXER_USERNAME, INDEXER_PASSWORD,
 * BENIGN_INTERVAL_MS(기본 200), BENIGN_READ_WAIT_SECONDS(관찰 30s + 색인 여유, 기본 60)
 */
@EnabledIfEnvironmentVariable(named = "RUN_BENIGN_MEASURE", matches = "1")
class BenignRunIT {

    private static final Path CORPUS = Path.of("detections/corpus/benign/benign-corpus-v1.yaml");
    private static final Duration OBSERVATION = Duration.ofSeconds(30);

    private static String env(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(name + " 필요 (기본값 없음)");
        }
        return v.strip();
    }

    @Test
    void measure() throws Exception {
        String label = env("BENIGN_LABEL");
        Path ca = Path.of(env("INDEXER_CA_FILE"));
        assertTrue(Files.isReadable(ca), "INDEXER_CA_FILE 을 읽을 수 없다: " + ca);
        DataSource ds = new DriverManagerDataSource(
                "jdbc:postgresql://127.0.0.1:5433/" + env("POSTGRES_DB") + "?currentSchema=validation",
                "validation_rw", env("VALIDATION_DB_PASSWORD"));
        JdbcTemplate jdbc = new JdbcTemplate(ds);
        String schemaVersion = jdbc.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class);
        assertTrue(schemaVersion != null && Integer.parseInt(schemaVersion) >= 7,
                "운영 validation 스키마가 V7 미만이다(=" + schemaVersion + ") — RUNBOOK (1) 먼저 (이 진입점은 migrate 하지 않는다)");
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM validation.measurement_run WHERE label = ?",
                Integer.class, label), "같은 label run 이 이미 있다");
        Path repo = Path.of(".");
        GitState git = GitStateSource.cli(repo).read();
        assertFalse(git.dirty(), "git 작업 트리가 깨끗하지 않다 — git_dirty=f 로 측정한다(측정 로그는 /tmp 에)");

        BenignCorpus corpus = BenignCorpus.load(CORPUS);
        RulesDigest digest = RulesDigest.compute(repo);
        System.out.println("BENIGN>> corpus=" + corpus.name() + " file_sha256=" + BenignCorpus.fileSha256(CORPUS)
                + " git=" + git.commit() + " dirty=" + git.dirty());

        String indexer = "https://127.0.0.1:9200";
        String user = env("INDEXER_USERNAME");
        String pass = env("INDEXER_PASSWORD");
        BenignAlertReader alerts = new BenignAlertReader(
                new IndexerAlertSearchSource(indexer, "wazuh-alerts-*", user, pass, "vuln-webapp", ca),
                IndexerAlertSearchSource.forRuleId(indexer, "wazuh-alerts-*", user, pass, "86601", ca),
                Duration.ofSeconds(60));
        long interval = Long.parseLong(System.getenv().getOrDefault("BENIGN_INTERVAL_MS", "200"));
        long readWait = Long.parseLong(System.getenv().getOrDefault("BENIGN_READ_WAIT_SECONDS", "60"));
        MeasurementRunRepository runs = new MeasurementRunRepository(ds);

        UUID runId = new BenignWebRun(runs,
                expected -> MeasurementRun.open(label, MeasurementRun.Kind.BENIGN, Instant.now(), git, digest, expected, 0),
                new BenignCorpusRunner(new HttpBenignSender("http://127.0.0.1:8080", Duration.ofSeconds(15)),
                        System::currentTimeMillis, d -> Thread.sleep(d.toMillis()), Duration.ofMillis(interval)),
                new BenignLogReader(new DockerExecAttackLogSource(
                        "docker/docker-compose.yml", "security-lab", "target-web", "/var/log/target/attack.json.log")),
                alerts, new BenignAlertLinker(NidsSidCatalog.V1_7, OBSERVATION), new BenignRunRepository(ds),
                d -> Thread.sleep(d.toMillis()), Duration.ofSeconds(readWait), OBSERVATION, System::currentTimeMillis)
                .execute(corpus);

        Map<String, Object> r10 = jdbc.queryForMap("SELECT r10_status, r10_reason, expected_attempts, benign_loaded, "
                + "benign_matched FROM validation.v_run_integrity WHERE run_id = ?", runId);
        System.out.println("BENIGN>> run_id=" + runId + " R10=" + r10);
    }
}
