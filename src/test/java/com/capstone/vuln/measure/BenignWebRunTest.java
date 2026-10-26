package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * BenignWebRun (S4-5 (3-F) 수정 2·3): 사전 시험 실패 → run 없음·전송 0, 알림 읽기 실패 → benign_request(전송·응답 시각 포함)는
 * 남고 run 은 OPEN, 정상 → R10 VALID. 전송·앱 로그·인덱서는 가짜(요청 3건).
 */
class BenignWebRunTest extends ValidationDbFixture {

    private static final Instant T0 = Instant.parse("2026-10-22T03:00:00Z");
    private static final String EMPTY = "{\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"hits\":[]}}";

    private final AtomicLong clock = new AtomicLong(T0.toEpochMilli());
    private final List<String> appLog = new ArrayList<>();
    private final AtomicInteger sentCount = new AtomicInteger();
    private UUID openedRun;

    private static final BenignCorpus CORPUS = new BenignCorpus("test-corpus", "x", List.of(
            new BenignCorpus.Item(1, "/api/products/search", "keyword", "tablet"),
            new BenignCorpus.Item(2, "/api/files/download", "filename", "manual_v1.pdf"),
            new BenignCorpus.Item(3, "/api/preview", "url", "https://www.iana.org/help")));

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    /** 가짜 target-web: 요청마다 Caldera 헤더 없는 앱 로그 줄 1개(rid = r<n>)를 쓰고 20 ms 뒤 응답 */
    private BenignSender sender() {
        return target -> {
            int n = sentCount.incrementAndGet();
            BenignCorpus.Item it = CORPUS.items().get(n - 1);
            appLog.add("{\"time\":" + (clock.get() + 5) + ",\"rid\":\"r" + n + "\",\"http_request\":{\"url\":{\"path\":\""
                    + it.endpoint() + "\"},\"args\":\"" + it.appArgs() + "\"},\"correlation\":{\"op_id\":null}}");
            clock.addAndGet(20);
            return 200;
        };
    }

    private BenignWebRun run(AlertSearchSource app, AlertSearchSource nids) {
        BenignCorpusRunner.Sleeper sleep = d -> clock.addAndGet(d.toMillis());
        return new BenignWebRun(new MeasurementRunRepository(DS),
                expected -> {
                    MeasurementRun r = MeasurementRun.open("benign-web-test-" + UUID.randomUUID(), MeasurementRun.Kind.BENIGN,
                            Instant.ofEpochMilli(clock.get()), new GitState("test", false),
                            new RulesDigest("w", "s", "a", new TreeMap<>()), expected, 0);
                    openedRun = r.runId();
                    return r;
                },
                new BenignCorpusRunner(sender(), clock::get, sleep, Duration.ofMillis(200)),
                new BenignLogReader(() -> String.join("\n", appLog)),
                new BenignAlertReader(app, nids, Duration.ofSeconds(60)),
                new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30)),
                new BenignRunRepository(DS), sleep, Duration.ofSeconds(60), Duration.ofSeconds(30), clock::get);
    }

    @Test
    void preflightFailureOpensNoRunAndSendsNothing() {
        AlertSearchSource broken = (from, to) -> { throw new IllegalStateException("인덱서 alert 질의 I/O 실패"); };
        assertThrows(IllegalStateException.class, () -> run(broken, (f, t) -> EMPTY).execute(CORPUS));
        assertEquals(0, sentCount.get());
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.measurement_run", Integer.class));
    }

    /** 사전 시험(앱 룰 1번 호출)은 통과, 본 읽기에서 실패 → 전송 기록은 sent_at·responded_at 그대로 남고 run 은 OPEN */
    @Test
    void alertReadFailureAfterSendingKeepsRequestsWithSentTimes() {
        AtomicInteger calls = new AtomicInteger();
        AlertSearchSource failsAfterPreflight = (from, to) -> {
            if (calls.incrementAndGet() > 1) {
                throw new IllegalStateException("인덱서 alert 질의 I/O 실패");
            }
            return EMPTY;
        };
        assertThrows(IllegalStateException.class, () -> run(failsAfterPreflight, (f, t) -> EMPTY).execute(CORPUS));

        assertEquals(3, sentCount.get());
        List<Map<String, Object>> rows = JDBC.queryForList(
                "SELECT seq, sent_at, responded_at, status, matched_rid FROM validation.benign_request WHERE run_id = ? ORDER BY seq",
                openedRun);
        assertEquals(3, rows.size());
        // 전송 시각 = T0, T0+220, T0+440 (응답 20 ms + 간격 200 ms), 응답 = 전송 + 20 ms
        for (int i = 0; i < 3; i++) {
            Instant sent = T0.plusMillis(220L * i);
            assertEquals(sent, ((Timestamp) rows.get(i).get("sent_at")).toInstant());
            assertEquals(sent.plusMillis(20), ((Timestamp) rows.get(i).get("responded_at")).toInstant());
            assertEquals("r" + (i + 1), rows.get(i).get("matched_rid"));
        }
        Map<String, Object> r10 = JDBC.queryForMap(
                "SELECT status, r10_status, benign_loaded, benign_matched FROM validation.v_run_integrity WHERE run_id = ?",
                openedRun);
        assertEquals("OPEN", r10.get("status"));
        assertEquals("INCOMPLETE", r10.get("r10_status"));
        assertEquals(3L, ((Number) r10.get("benign_loaded")).longValue());
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.benign_result WHERE run_id = ?",
                Integer.class, openedRun));
    }

    @Test
    void successfulRunIsValidWithResults() throws Exception {
        UUID runId = run((f, t) -> EMPTY, (f, t) -> EMPTY).execute(CORPUS);
        Map<String, Object> r10 = JDBC.queryForMap(
                "SELECT status, r10_status, benign_loaded, benign_matched FROM validation.v_run_integrity WHERE run_id = ?",
                runId);
        assertEquals("CLOSED", r10.get("status"));
        assertEquals("VALID", r10.get("r10_status"));
        assertEquals(6, JDBC.queryForObject("SELECT count(*) FROM validation.benign_result WHERE run_id = ?",
                Integer.class, runId), "3요청 × (APP_RULE·NIDS)");
    }
}
