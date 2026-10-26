package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R17 c·R18 a~c·g — 순차 전송, 앱 로그 1:1 대조(순서+path+args+시각 창), 알림 연결(FP/TN), 미연결 기록.
 * 기대값은 픽스처를 손으로 센 값.
 */
class BenignWebPipelineTest {

    private static final Instant T0 = Instant.parse("2026-10-22T01:00:00Z");

    private static BenignCorpus.Item item(int seq, String endpoint, String param, String value) {
        return new BenignCorpus.Item(seq, endpoint, param, value);
    }

    private static final List<BenignCorpus.Item> ITEMS = List.of(
            item(1, "/api/products/search", "keyword", "galaxy s24"),
            item(2, "/api/files/download", "filename", "manual_v1.pdf"),
            item(3, "/api/preview", "url", "https://www.iana.org/help"),
            item(4, "/api/products/search", "keyword", "노트북 15인치"));

    // ---- 전송 ----

    /** 순차 1건씩, 요청 사이 간격, 브라우저형 UA·Caldera 헤더 없음(전송기 계약), 실패는 status -1 로 기록하고 계속 */
    @Test
    void runnerSendsSequentiallyWithIntervalAndRecordsTimes() {
        AtomicLong clock = new AtomicLong(T0.toEpochMilli());
        List<String> targets = new ArrayList<>();
        List<Long> sleeps = new ArrayList<>();
        BenignSender sender = target -> {
            targets.add(target);
            clock.addAndGet(30); // 응답까지 30 ms
            if (target.startsWith("/api/preview")) {
                throw new java.io.IOException("connect timeout");
            }
            return 200;
        };
        BenignCorpusRunner runner = new BenignCorpusRunner(sender, clock::get,
                d -> { sleeps.add(d.toMillis()); clock.addAndGet(d.toMillis()); }, Duration.ofMillis(200));

        List<BenignSent> sent = runner.run(ITEMS);

        assertEquals(List.of("/api/products/search?keyword=galaxy+s24", "/api/files/download?filename=manual_v1.pdf",
                "/api/preview?url=https%3A%2F%2Fwww.iana.org%2Fhelp",
                "/api/products/search?keyword=%EB%85%B8%ED%8A%B8%EB%B6%81+15%EC%9D%B8%EC%B9%98"), targets);
        assertEquals(List.of(200L, 200L, 200L), sleeps, "요청 사이 간격 3번(마지막 뒤 없음)");
        assertEquals(T0, sent.get(0).sentAt());
        assertEquals(T0.plusMillis(30), sent.get(0).respondedAt());
        assertEquals(T0.plusMillis(230), sent.get(1).sentAt());
        assertEquals(-1, sent.get(2).status());
        assertEquals(200, sent.get(3).status());
        assertTrue(BenignSender.USER_AGENT.startsWith("Mozilla/5.0"));
        assertFalse(BenignSender.USER_AGENT.contains("Caldera"));
    }

    private static List<BenignSent> sentAt(long... offsets) {
        List<BenignSent> out = new ArrayList<>();
        for (int i = 0; i < ITEMS.size(); i++) {
            BenignCorpus.Item it = ITEMS.get(i);
            out.add(new BenignSent(it.seq(), it.endpoint(), it.requestTarget(), it.appArgs(),
                    T0.plusMillis(offsets[i]), T0.plusMillis(offsets[i] + 40), 200));
        }
        return out;
    }

    private static String appLine(long ms, String rid, String path, String args, String paw) {
        String corr = paw == null ? "{\"op_id\":null,\"ability_id\":null,\"source\":\"NONE\"}"
                : "{\"op_id\":\"" + paw + "\",\"ability_id\":\"a\",\"source\":\"HEADER\"}";
        return "{\"time\":" + (T0.toEpochMilli() + ms) + ",\"rid\":\"" + rid + "\",\"http_request\":{\"http_method\":\"GET\","
                + "\"url\":{\"path\":\"" + path + "\"},\"args\":\"" + args + "\"},\"correlation\":" + corr + "}";
    }

    // ---- 앱 로그 대조 (R17 c) ----

    /**
     * 요청 4건(0, 500, 1000, 1500 ms 전송, 각 40 ms 응답). 앱 로그: 대조 대상 4줄 + Caldera 태깅 줄(제외) + 창 밖 같은 args 줄(제외)
     * + seq 2 와 args 가 다른 줄(대조 안 됨). seq 4 는 로그 없음 → 대조 실패.
     */
    @Test
    void logReaderMatchesByOrderPathArgsAndTimeWindow() {
        String log = String.join("\n",
                appLine(-5_000, "old", "/api/products/search", "keyword=galaxy s24", null),   // 창 밖
                appLine(10, "r1", "/api/products/search", "keyword=galaxy s24", null),
                appLine(20, "cal", "/api/products/search", "keyword=galaxy s24", "eiwwvn"),   // Caldera 태깅
                appLine(510, "rx", "/api/files/download", "filename=other.pdf", null),       // args 다름
                appLine(515, "r2", "/api/files/download", "filename=manual_v1.pdf", null),
                appLine(1010, "r3", "/api/preview", "url=https://www.iana.org/help", null),
                "not json");
        BenignLogReader.Match m = new BenignLogReader(() -> log).match(sentAt(0, 500, 1000, 1500));

        assertEquals(Map.of(1, "r1", 2, "r2", 3, "r3"), m.ridBySeq());
        assertEquals(1, m.unmatchedUntaggedLines(), "창 안 Caldera 헤더 없는 줄 중 대조 안 된 것 = rx");
    }

    // ---- 알림 연결 (R18 a~c·g) ----

    private static BenignNidsAlert nids(int sid, long eventMs, long alertMs, String url, String src) {
        return new BenignNidsAlert(sid, T0.plusMillis(alertMs), T0.plusMillis(eventMs), url, src, "172.20.0.3");
    }

    /**
     * 대조: seq1=r1, seq2=r2, seq3=r3, seq4=r4. 알림:
     *  APP_RULE 100210 rid r1 (FP), APP_RULE 100002 rid 없음(미연결), APP_RULE 100220 rid zz(미연결)
     *  NIDS 1000013 seq1 url·창 일치(ANALYTIC → FP), NIDS 1000001 seq2 일치(MARKER → 기록만),
     *  NIDS 1000060 seq3 url 일치·eve 시각 창 밖(후보 0 → 미연결), NIDS 1000020 배경 fe80 (기록 제외),
     *  NIDS 1000013 seq4 url 일치·Wazuh 시각이 응답+30s 넘음(후보 0 → 미연결)
     */
    @Test
    void linkerCountsFpPerRequestAndControlAndRecordsUnlinked() {
        List<BenignSent> sent = sentAt(0, 500, 1000, 1500);
        Map<Integer, String> rids = Map.of(1, "r1", 2, "r2", 3, "r3", 4, "r4");
        List<BenignAppAlert> app = List.of(
                new BenignAppAlert("100210", "r1", T0.plusMillis(900)),
                new BenignAppAlert("100002", null, T0.plusMillis(900)),
                new BenignAppAlert("100220", "zz", T0.plusMillis(900)));
        List<BenignNidsAlert> nidsAlerts = List.of(
                nids(1000013, 5, 1_400, sent.get(0).requestTarget(), "172.20.0.1"),
                nids(1000001, 505, 1_900, sent.get(1).requestTarget(), "172.20.0.1"),
                nids(1000060, 2_000, 2_900, sent.get(2).requestTarget(), "172.20.0.1"),
                nids(1000020, 505, 1_900, "/x", "fe80::1"),
                nids(1000013, 1_505, 1_540 + 30_001, sent.get(3).requestTarget(), "172.20.0.1"));

        BenignAlertLinker.Result r = new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30))
                .link(sent, rids, app, nidsAlerts);

        Map<String, BenignResult> by = new java.util.HashMap<>();
        r.results().forEach(x -> by.put(x.seq() + ":" + x.control(), x));
        assertEquals(8, r.results().size(), "4요청 × (APP_RULE·NIDS) — BACKEND_CORR 는 웹 엔드포인트에 적용 안 됨");
        assertTrue(by.get("1:APP_RULE").alerted());
        assertEquals(List.of("100210"), by.get("1:APP_RULE").linkedRuleIds());
        assertTrue(by.get("1:NIDS").alerted());
        assertFalse(by.get("2:NIDS").alerted());
        assertEquals(List.of("1000001"), by.get("2:NIDS").recordedRuleIds());
        assertFalse(by.get("3:NIDS").alerted());
        assertFalse(by.get("4:NIDS").alerted());
        assertFalse(by.get("2:APP_RULE").alerted());
        assertEquals(0, by.get("2:APP_RULE").alertCount());

        List<String> unlinked = r.unlinked().stream()
                .map(u -> u.sensor() + ":" + u.ruleId() + ":" + u.reason()).sorted().toList();
        assertEquals(List.of("APP_RULE:100002:NO_MATCH", "APP_RULE:100220:NO_MATCH",
                "NIDS:1000013:NO_CANDIDATE", "NIDS:1000060:NO_CANDIDATE"), unlinked);
    }

    /** 대조 실패(rid 없음) 요청은 결과 행을 만들지 않는다 — R10 이 INVALID 로 막는다 */
    @Test
    void unmatchedRequestsGetNoResultRows() {
        BenignAlertLinker.Result r = new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30))
                .link(sentAt(0, 500, 1000, 1500), Map.of(1, "r1"), List.of(), List.of());
        assertEquals(2, r.results().size());
        r.results().forEach(x -> assertEquals(1, x.seq()));
    }

    /** 같은 url·창에 요청이 둘이면 연결하지 않는다(AMBIGUOUS) */
    @Test
    void ambiguousNidsCandidateIsUnlinked() {
        BenignCorpus.Item a = item(1, "/api/products/search", "keyword", "tablet");
        List<BenignSent> sent = List.of(
                new BenignSent(1, a.endpoint(), a.requestTarget(), a.appArgs(), T0, T0.plusMillis(100), 200),
                new BenignSent(2, a.endpoint(), a.requestTarget(), a.appArgs(), T0.plusMillis(50), T0.plusMillis(150), 200));
        BenignAlertLinker.Result r = new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30))
                .link(sent, Map.of(1, "r1", 2, "r2"), List.of(),
                        List.of(nids(1000013, 70, 900, a.requestTarget(), "172.20.0.1")));
        assertEquals("AMBIGUOUS", r.unlinked().get(0).reason());
        r.results().forEach(x -> assertFalse(x.alerted()));
    }

    // ---- 알림 읽기 (R18 c) ----

    private static final String APP_PAGE = """
            {"hits":{"total":{"value":2,"relation":"eq"},"hits":[
              {"_source":{"timestamp":"2026-10-22T01:00:01.000+0000","rule":{"id":"100210"},"data":{"rid":"r1"}}},
              {"_source":{"timestamp":"2026-10-22T01:00:02.000+0000","rule":{"id":"100002"},"data":{"id":"x"}}}]}}""";
    private static final String NIDS_PAGE = """
            {"hits":{"total":{"value":1,"relation":"eq"},"hits":[
              {"_source":{"timestamp":"2026-10-22T01:00:01.500+0000","rule":{"id":"86601"},
                "data":{"timestamp":"2026-10-22T01:00:00.005123+0000","src_ip":"172.20.0.1","dest_ip":"172.20.0.3",
                        "alert":{"signature_id":"1000013"},"http":{"url":"/api/products/search?keyword=%27"}}}}]}}""";

    /** 창을 조각으로 나눠 읽는다(조각마다 검색 상한 확인). 조각 경계는 겹치지 않는다 */
    @Test
    void alertReaderReadsInNonOverlappingChunks() {
        List<String> calls = new ArrayList<>();
        BenignAlertReader reader = new BenignAlertReader(
                (from, to) -> { calls.add("app " + from + " " + to); return calls.size() == 1 ? APP_PAGE : "{\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"hits\":[]}}"; },
                (from, to) -> NIDS_PAGE, Duration.ofSeconds(60));

        List<BenignAppAlert> app = reader.readApp(T0, T0.plusSeconds(90));
        assertEquals(List.of("app " + T0 + " " + T0.plusMillis(59_999), "app " + T0.plusSeconds(60) + " " + T0.plusSeconds(90)),
                calls);
        assertEquals(2, app.size());
        assertEquals("r1", app.get(0).rid());
        assertNull(app.get(1).rid());

        BenignNidsAlert n = reader.readNids(T0, T0.plusSeconds(30)).get(0);
        assertEquals(1000013, n.sid());
        assertEquals(Instant.parse("2026-10-22T01:00:00.005123Z"), n.eventTime());
        assertEquals("/api/products/search?keyword=%27", n.url());
        assertEquals("172.20.0.3", n.destIp());
    }

    @Test
    void alertReaderRefusesTruncatedChunk() {
        BenignAlertReader reader = new BenignAlertReader(
                (from, to) -> APP_PAGE.replace("\"value\":2", "\"value\":2500"), (from, to) -> NIDS_PAGE,
                Duration.ofSeconds(60));
        assertThrows(IllegalStateException.class, () -> reader.readApp(T0, T0.plusSeconds(10)));
    }
}
