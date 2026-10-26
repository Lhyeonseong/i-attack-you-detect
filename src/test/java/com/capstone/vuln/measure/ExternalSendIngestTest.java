package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ExternalSendIngest (ADR-S4-01 v2.0 R17 f·R18 j) — 외부 전송 결과 CSV ingest. open/ingest, §I 무결성, login 적재·연결·R10.
 * 알림은 가짜(EMPTY = FP 0). 계정은 login-plan 과 같은 형식의 소규모 가짜 계획(비밀번호 없음). 테스트 컨테이너 DB(V9 까지 migrate).
 */
class ExternalSendIngestTest extends ValidationDbFixture {

    private static final Instant T0 = Instant.parse("2026-10-22T06:00:00Z");
    private static final String EMPTY = "{\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"hits\":[]}}";

    private static final LoginPlan PLAN = new LoginPlan(List.of(
            new LoginPlan.Entry(1, "SEED_USER1", "user1", "NORMAL"),
            new LoginPlan.Entry(2, "SEED_USER2", "user2", "TYPO"),
            new LoginPlan.Entry(3, "SEED_USER2", "user2", "NORMAL")));

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    private UUID openRun() {
        MeasurementRunRepository runs = new MeasurementRunRepository(DS);
        return new ExternalSendIngest(DS, runs, null).open(
                expected -> MeasurementRun.open("login-" + UUID.randomUUID(), MeasurementRun.Kind.BENIGN,
                        T0, new GitState("test", false), new RulesDigest("w", "s", "a", new TreeMap<>()), expected, 0),
                PLAN, LoginPlan.ENDPOINT);
    }

    /** 가짜 앱 로그: 요청마다 Caldera 헤더 없는 /api/auth/login 줄(rid r<seq>, args username=<plan user>) */
    private static String appLog() {
        List<String> lines = new ArrayList<>();
        for (LoginPlan.Entry e : PLAN.entries()) {
            long mid = 500L * (e.seq() - 1) + 20;
            lines.add("{\"time\":" + (T0.toEpochMilli() + mid) + ",\"rid\":\"r" + e.seq() + "\","
                    + "\"http_request\":{\"url\":{\"path\":\"/api/auth/login\"},\"args\":\"username=" + e.username() + "\"},"
                    + "\"correlation\":{\"op_id\":null}}");
        }
        return String.join("\n", lines);
    }

    private ExternalSendIngest ingest(String appLog) {
        MeasurementRunRepository runs = new MeasurementRunRepository(DS);
        BenignIngest pipeline = new BenignIngest(runs, new BenignLogReader(() -> appLog),
                new BenignAlertReader((f, t) -> EMPTY, (f, t) -> EMPTY, Duration.ofSeconds(60)),
                new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30)),
                new BenignRunRepository(DS), Duration.ofSeconds(30), () -> T0.plusSeconds(60).toEpochMilli());
        return new ExternalSendIngest(DS, runs, pipeline);
    }

    /** 결과 CSV 작성 — 각 요청 500 ms 간격(§I 충족), 40 ms 응답 */
    private Path resultCsv(Path dir, long... spacingMs) throws Exception {
        List<String> lines = new ArrayList<>(List.of(ExternalSendIngest.RESULT_HEADER));
        long t = T0.toEpochMilli();
        for (int i = 0; i < PLAN.size(); i++) {
            long sent = t + (spacingMs.length == 0 ? 500L * i : spacingMs[i]);
            lines.add((i + 1) + "," + sent + "," + (sent + 40) + "," + (i == 1 ? 401 : 200));
        }
        Path f = dir.resolve("result.csv");
        Files.write(f, lines);
        return f;
    }

    @Test
    void normalIngestIsValidWithLoginControlRows(@TempDir Path dir) throws Exception {
        UUID runId = openRun();
        ingest(appLog()).ingest(runId, PLAN, resultCsv(dir));

        Map<String, Object> r10 = JDBC.queryForMap("SELECT status, r10_status, expected_attempts, benign_loaded, "
                + "benign_matched FROM validation.v_run_integrity WHERE run_id = ?", runId);
        assertEquals("CLOSED", r10.get("status"));
        assertEquals("VALID", r10.get("r10_status"));
        assertEquals(3L, ((Number) r10.get("benign_loaded")).longValue());
        assertEquals(3L, ((Number) r10.get("benign_matched")).longValue());
        assertEquals(3, JDBC.queryForObject("SELECT count(*) FROM validation.benign_request WHERE run_id = ?",
                Integer.class, runId));
        // login = BACKEND_CORR·NIDS 각 3행(APP_RULE 없음), FP 0
        assertEquals(6, JDBC.queryForObject("SELECT count(*) FROM validation.benign_result WHERE run_id = ?",
                Integer.class, runId));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.benign_result WHERE run_id = ? AND control = 'APP_RULE'",
                Integer.class, runId));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.benign_result WHERE run_id = ? AND alerted",
                Integer.class, runId));
    }

    /** 단일 후보 조건 위반(seq2 전송이 seq1 응답 + 2×TOLERANCE 안) → 적재 전 실패, run OPEN, 사유 notes, benign_request 0 */
    @Test
    void singleCandidateViolationKeepsOpenAndRecordsReason(@TempDir Path dir) throws Exception {
        UUID runId = openRun();
        // seq1 sent=0 resp=40, seq2 sent=120 (120-40=80 ≤ 100) → 위반
        Path bad = resultCsv(dir, 0, 120, 700);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> ingest(appLog()).ingest(runId, PLAN, bad));
        assertTrue(ex.getMessage().contains("단일 후보"), ex.getMessage());

        Map<String, Object> row = JDBC.queryForMap("SELECT status, notes FROM validation.measurement_run WHERE run_id = ?", runId);
        assertEquals("OPEN", row.get("status"));
        assertTrue(((String) row.get("notes")).contains("단일 후보"), (String) row.get("notes"));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.benign_request WHERE run_id = ?",
                Integer.class, runId));
    }

    /** seq 누락·형식 오류 CSV → 실패, 적재 0 */
    @Test
    void malformedCsvFails(@TempDir Path dir) throws Exception {
        UUID runId = openRun();
        Path missingSeq = dir.resolve("gap.csv");
        Files.write(missingSeq, List.of(ExternalSendIngest.RESULT_HEADER,
                "1," + T0.toEpochMilli() + "," + (T0.toEpochMilli() + 40) + ",200",
                "3," + (T0.toEpochMilli() + 1000) + "," + (T0.toEpochMilli() + 1040) + ",200"));
        assertThrows(IllegalStateException.class, () -> ingest(appLog()).ingest(runId, PLAN, missingSeq));

        Path badHeader = dir.resolve("hdr.csv");
        Files.write(badHeader, List.of("seq,sent,resp,status", "1,0,40,200"));
        assertThrows(IllegalStateException.class, () -> ingest(appLog()).ingest(runId, PLAN, badHeader));

        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.benign_request WHERE run_id = ?",
                Integer.class, runId));
    }

    @Test
    void openRejectsUnknownEndpoint() {
        MeasurementRunRepository runs = new MeasurementRunRepository(DS);
        assertThrows(IllegalStateException.class, () -> new ExternalSendIngest(DS, runs, null).open(
                expected -> MeasurementRun.open("x", MeasurementRun.Kind.BENIGN, T0, new GitState("t", false),
                        new RulesDigest("w", "s", "a", new TreeMap<>()), expected, 0),
                PLAN, "/api/not/registered"));
    }

    /** D7: login BENIGN run 은 ATTACK 지표 뷰에 안 섞인다 — M14 뷰에만 나온다 */
    @Test
    void benignLoginRunStaysOutOfAttackViews(@TempDir Path dir) throws Exception {
        UUID runId = openRun();
        ingest(appLog()).ingest(runId, PLAN, resultCsv(dir));

        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_rates WHERE run_id = ?",
                Integer.class, runId), "BENIGN run 은 M01~M03 등 ATTACK 뷰에 없다(D7)");
        assertTrue(JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m14a WHERE run_id = ?",
                Integer.class, runId) > 0, "M14a 에는 나온다");
        assertEquals(List.of("ADR-S4-01 v2.0"), JDBC.queryForList("SELECT DISTINCT definition_version FROM "
                + "validation.v_metric_m14a WHERE run_id = ?", String.class, runId));
    }
}
