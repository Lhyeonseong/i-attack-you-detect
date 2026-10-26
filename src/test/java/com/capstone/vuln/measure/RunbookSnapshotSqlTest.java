package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RUNBOOK-S4-5-benign.md (4-S) 스냅샷 SQL 블록을 파일에서 그대로 꺼내 psql(-f, -v run·pair·before, ON_ERROR_STOP)로 실행한다.
 * 운영과 같은 모양: 짝 ATTACK run(VALID·스냅샷 있음, 같은 rules_digest) + 웹 BENIGN run(엔드포인트 3) → M14a 9 + M14b 3 = 12행.
 * psql 변수 치환 규칙(달러 인용 안은 치환 안 함)도 같은 컨테이너에서 재현한다. 스냅샷 불변 행 → 전용 컨테이너.
 */
class RunbookSnapshotSqlTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        // (4-S) 는 웹 run(3818e21a)의 완료된 스냅샷 단계 — v1.9(V8) 에서 실행됐다. 그 블록의 DO 검사가 v1.9 를
        // 기대하므로 이 테스트는 V8 에 고정한다. login 의 v2.0 스냅샷은 (3-L)·V9MigrationTest 가 따로 본다.
        JDBC = new JdbcTemplate(ValidationDbFixture.bootstrap(PG, "8"));
    }

    private static final Path RUNBOOK = Path.of("detections/measurements/RUNBOOK-S4-5-benign.md");
    private static final String DIGEST = "{\"wazuh_rules\":\"runbook\"}";

    /** (4-S) 절의 here-doc 중 take_metric_snapshot 을 부르는 블록 본문 */
    static String snapshotBlock() throws Exception {
        List<String> lines = Files.readAllLines(RUNBOOK, StandardCharsets.UTF_8);
        int section = -1;
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).startsWith("## (4-S) ")) {
                section = i;
            }
        }
        assertTrue(section >= 0, "(4-S) 절 없음");
        List<String> body = null;
        for (int i = section; i < lines.size() && !(i > section && lines.get(i).startsWith("## ")); i++) {
            if (body == null && lines.get(i).contains("<<'SQL'")) {
                body = new ArrayList<>();
            } else if (body != null && lines.get(i).equals("SQL")) {
                String text = String.join("\n", body) + "\n";
                if (text.contains("take_metric_snapshot")) {
                    return text;
                }
                body = null;
            } else if (body != null) {
                body.add(lines.get(i));
            }
        }
        throw new AssertionError("(4-S) 스냅샷 SQL 블록 없음");
    }

    private static ExecResult psql(String sql, String... vars) throws Exception {
        Path file = Files.createTempFile("runbook-4s", ".sql");
        Files.writeString(file, sql);
        PG.copyFileToContainer(MountableFile.forHostPath(file), "/tmp/runbook-4s.sql");
        List<String> cmd = new ArrayList<>(List.of("psql", "-U", "validation_rw", "-d", PG.getDatabaseName(),
                "-v", "ON_ERROR_STOP=1"));
        for (String v : vars) {
            cmd.add("-v");
            cmd.add(v);
        }
        cmd.add("-f");
        cmd.add("/tmp/runbook-4s.sql");
        return PG.execInContainer(cmd.toArray(String[]::new));
    }

    private static UUID pairRun() {
        UUID run = new MetricFixture(JDBC).nidsCollected()
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100220").ctl("NIDS", "1000020"))
                .close(MetricFixture.Close.VALID);
        JDBC.update("UPDATE validation.measurement_run SET rules_digest = ?::jsonb WHERE run_id = ?", DIGEST, run);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        return run;
    }

    private static UUID webRun() {
        return new BenignFixture(JDBC, DIGEST)
                .requests("/api/products/search", 3, 3, 0, 0)
                .requests("/api/files/download", 3, 3, 1, 0)
                .requests("/api/preview", 3, 3, 0, 1)
                .close(9, true);
    }

    private static int rows(UUID run) {
        return JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot WHERE run_id = ?", Integer.class, run);
    }

    private static int total() {
        return JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot", Integer.class);
    }

    /** psql 은 달러 인용 문자열 안의 :'var' 를 치환하지 않는다 — 바깥은 치환, DO 안은 그대로 서버로 가서 문법 오류 */
    @Test
    void psqlDoesNotSubstituteVariablesInsideDollarQuotes() throws Exception {
        String sql = """
                SELECT :'run'::uuid AS outside;
                DO $x$ BEGIN PERFORM :'run'::uuid; END $x$;
                """;
        ExecResult r = psql(sql, "run=" + UUID.randomUUID());
        assertEquals(3, r.getExitCode(), r.getStdout() + r.getStderr());
        assertTrue(r.getStdout().contains("outside"), r.getStdout());
        assertTrue(r.getStderr().contains("syntax error at or near \":\""), r.getStderr());
    }

    /** (a) 정상 값 → COMMIT, 12행, 총 행 = before + 12 */
    @Test
    void runbookBlockCommitsTwelveRowsWhenChecksPass() throws Exception {
        UUID pair = pairRun();
        UUID web = webRun();
        int before = total();

        ExecResult r = psql(snapshotBlock(), "run=" + web, "pair=" + pair, "before=" + before);

        assertEquals(0, r.getExitCode(), r.getStdout() + r.getStderr());
        assertTrue(r.getStdout().contains("COMMIT"), r.getStdout());
        assertEquals(12, rows(web));
        assertEquals(before + 12, total());
        assertEquals(3, JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot WHERE run_id = ? "
                + "AND paired_run_id = ?", Integer.class, web, pair));
    }

    /** (b) 기대 어긋남(before 를 틀리게) → snapshot check failed 예외, COMMIT 전 중단 → 0행 롤백 */
    @Test
    void runbookBlockRollsBackWhenChecksFail() throws Exception {
        UUID pair = pairRun();
        UUID web = webRun();
        int before = total();

        ExecResult r = psql(snapshotBlock(), "run=" + web, "pair=" + pair, "before=" + (before + 1));

        assertEquals(3, r.getExitCode(), r.getStdout() + r.getStderr());
        assertTrue(r.getStderr().contains("snapshot check failed"), r.getStderr());
        assertTrue(!r.getStdout().contains("COMMIT"), r.getStdout());
        assertEquals(0, rows(web));
        assertEquals(before, total());
    }
}
