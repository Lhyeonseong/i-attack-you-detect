package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R14 a·b 입력 읽기 — Wazuh 86601 alert(AlertIndexReader.readNids), eve.json http(EveTelemetryReader), 질의 본문.
 * 샘플 필드 형식은 2026-10-21 design-check 로그 C1 실측(flow_id 실수 문자열, signature_id·tx_id 문자열).
 */
class NidsReadersTest {

    private static final Instant FROM = Instant.parse("2026-10-21T10:00:00Z");
    private static final Instant TO = Instant.parse("2026-10-21T10:10:00Z");

    private static final String NIDS_SAMPLE = """
            {"hits":{"total":{"value":3,"relation":"eq"},"hits":[
              {"_source":{"timestamp":"2026-10-21T10:03:47.641+0000","rule":{"id":"86601"},
                "data":{"flow_id":"578501012733101.000000","tx_id":"0","src_ip":"172.20.0.1",
                        "alert":{"signature_id":"1000001"},"http":{"url":"/api/products/search?keyword=%27"}}}},
              {"_source":{"timestamp":"2026-10-21T10:03:48.000+0000","searchableTime":"2026-10-21T10:03:49.500+0000",
                "rule":{"id":"86601"},
                "data":{"flow_id":"12.500000","tx_id":"1","src_ip":"172.20.0.1","alert":{"signature_id":"1000020"}}}},
              {"_source":{"timestamp":"2026-10-21T10:03:49.000+0000","rule":{"id":"86601"},
                "data":{"tx_id":"0","alert":{"signature_id":"1000031"}}}}
            ]}}""";

    @Test
    void readNidsParsesFloatFormattedFlowIdAndStringSid() {
        List<NidsAlert> alerts = new AlertIndexReader(null, (from, to) -> NIDS_SAMPLE).readNids(FROM, TO);

        assertEquals(3, alerts.size());
        NidsAlert a = alerts.get(0);
        assertEquals(1000001, a.sid());
        assertEquals(Instant.parse("2026-10-21T10:03:47.641Z"), a.alertTime());
        assertNull(a.searchableTime());
        assertEquals(578501012733101L, a.flowId());
        assertEquals(0L, a.txId());
        assertEquals("172.20.0.1", a.srcIp());

        assertNull(alerts.get(1).flowId(), "소수부가 0 이 아닌 flow_id 는 연결하지 않는다");
        assertEquals(Instant.parse("2026-10-21T10:03:49.500Z"), alerts.get(1).searchableTime());
        assertNull(alerts.get(2).flowId(), "flow_id 없음");
    }

    /** 검색 상한(size)보다 많으면 일부만 읽은 것이므로 측정 실패로 멈춘다 */
    @Test
    void readNidsRefusesTruncatedResult() {
        String truncated = NIDS_SAMPLE.replace("\"value\":3", "\"value\":2001");
        AlertIndexReader reader = new AlertIndexReader(null, (from, to) -> truncated);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> reader.readNids(FROM, TO));
        assertTrue(e.getMessage().contains("2001"), e.getMessage());
    }

    @Test
    void readNidsWithoutSourceIsEmpty() {
        assertTrue(new AlertIndexReader((from, to) -> "{}").readNids(FROM, TO).isEmpty());
    }

    @Test
    void nidsQueryFiltersByRuleIdNotGroup() {
        String body = IndexerAlertSearchSource.ruleIdSearchBody(1000L, 2000L, "86601");
        assertTrue(body.contains("\"term\":{\"rule.id\":\"86601\"}"), body);
        assertFalse(body.contains("rule.groups"), body);
        assertTrue(body.contains("\"gte\":1000") && body.contains("\"lte\":2000"), body);
        // 기존 vuln-webapp 질의는 그대로
        assertTrue(IndexerAlertSearchSource.searchBody(1000L, 2000L, "vuln-webapp")
                .contains("\"term\":{\"rule.groups\":\"vuln-webapp\"}"));
    }

    // eve.json: http 2건(창 안 1, 창 밖 1), alert 1건, flow 1건, 깨진 줄 1개(eve.json 에는 바이너리 바이트가 섞인다)
    private static final String EVE = String.join("\n",
            "{\"timestamp\":\"2026-10-21T10:03:46.211837+0000\",\"flow_id\":578501012733101,\"event_type\":\"http\","
                    + "\"src_ip\":\"172.20.0.1\",\"dest_ip\":\"172.20.0.3\",\"dest_port\":8080,\"tx_id\":0,"
                    + "\"http\":{\"url\":\"/api/products/search?keyword=%27\","
                    + "\"http_user_agent\":\"Caldera/eiwwvn/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c\"}}",
            "{\"timestamp\":\"2026-10-21T10:03:46.211837+0000\",\"flow_id\":578501012733101,\"event_type\":\"alert\","
                    + "\"tx_id\":0,\"alert\":{\"signature_id\":1000001}}",
            "\u0000ÿ{broken",
            "{\"timestamp\":\"2026-10-21T10:03:46.300000+0000\",\"flow_id\":1,\"event_type\":\"flow\"}",
            "{\"timestamp\":\"2026-10-21T11:00:00.000000+0000\",\"flow_id\":2,\"event_type\":\"http\",\"tx_id\":0,"
                    + "\"http\":{\"url\":\"/x\"}}",
            "");

    @Test
    void eveReaderKeepsOnlyHttpInWindow() {
        List<EveHttp> http = new EveTelemetryReader(() -> EVE).read(FROM, TO);

        assertEquals(1, http.size());
        EveHttp h = http.get(0);
        assertEquals(578501012733101L, h.flowId());
        assertEquals(0L, h.txId());
        assertEquals(Instant.parse("2026-10-21T10:03:46.211837Z"), h.time());
        assertEquals("/api/products/search?keyword=%27", h.url());
        assertEquals("Caldera/eiwwvn/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c", h.userAgent());
        assertEquals("172.20.0.3", h.destIp());
        assertEquals(8080, h.destPort());
    }
}
