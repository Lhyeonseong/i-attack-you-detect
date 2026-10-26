package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GtLogReaderTest {

    private static final long START = 1_000_000_000_000L; // opStart epoch ms
    private static final Instant WINDOW_START = Instant.ofEpochMilli(START);
    private static final Instant WINDOW_END = Instant.ofEpochMilli(START + 30_000);

    // 창 안 SQLi(성공) + BF(실패), 창 밖(과거) 1줄, 수동(op_id null) 1줄 — 뒤 둘은 제외돼야 함
    private static final String SAMPLE = """
            {"time":1000000005000,"rid":"rid-sqli","correlation":{"op_id":"mcukpa","ability_id":"abil-sqli","source":"HEADER"},"validation":{"outcome":"SUCCEEDED","technique_id":"T1190"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/products/search"},"args":"q=1"}}
            {"time":1000000010000,"rid":"rid-bf","correlation":{"op_id":"mcukpa","ability_id":"7aa89a87","source":"HEADER"},"validation":{"outcome":"FAILED","technique_id":"T1110"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/auth/login"},"args":"username=user1&password=secret"}}
            {"time":999999940000,"rid":"rid-old","correlation":{"op_id":"mcukpa","ability_id":"abil-sqli","source":"HEADER"},"validation":{"outcome":"SUCCEEDED","technique_id":"T1190"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/products/search"}}}
            {"time":1000000006000,"rid":"rid-manual","correlation":{"op_id":null,"ability_id":null,"source":"NONE"},"validation":{"outcome":"SUCCEEDED","technique_id":"T1190"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/products/search"}}}
            """;

    private List<AttackEvent> read() {
        return new GtLogReader(() -> SAMPLE).read(WINDOW_START, WINDOW_END);
    }

    @Test
    void parses_only_in_window_caldera_tagged_lines() {
        List<AttackEvent> events = read();
        // 창 밖(과거) + 수동(op_id null) 제외 → 2건
        assertEquals(2, events.size());
        assertTrue(events.stream().noneMatch(e -> "rid-old".equals(e.key().rid())));
        assertTrue(events.stream().noneMatch(e -> "rid-manual".equals(e.key().rid())));
    }

    @Test
    void maps_fields_and_scenario_from_path() {
        Map<String, AttackEvent> byRid = read().stream()
                .collect(Collectors.toMap(e -> e.key().rid(), Function.identity()));

        AttackEvent sqli = byRid.get("rid-sqli");
        assertEquals("SQLI", sqli.scenario());               // /api/products/search → SQLI
        assertEquals("T1190", sqli.techniqueId());
        assertEquals(GroundTruthOutcome.SUCCEEDED, sqli.gtOutcome());
        assertEquals(Instant.ofEpochMilli(START + 5_000), sqli.attackTime()); // epoch ms
        assertEquals("mcukpa", sqli.key().agentPaw());       // correlation.op_id = paw
        assertEquals("172.20.0.1", sqli.srcIp());
        assertNull(sqli.username());                         // 로그인 아님 → username 없음

        AttackEvent bf = byRid.get("rid-bf");
        assertEquals("BRUTE_FORCE", bf.scenario());          // /api/auth/login → BRUTE_FORCE
        assertEquals(GroundTruthOutcome.FAILED, bf.gtOutcome());
        assertEquals("user1", bf.username());                // args 에서 username 만 추출(비번 무시)
        assertEquals("7aa89a87", bf.key().abilityId());
    }

    @Test
    void unmapped_path_is_UNKNOWN_scenario_not_silent_misclassify() {
        String line = "{\"time\":1000000007000,\"rid\":\"rid-x\",\"correlation\":{\"op_id\":\"mcukpa\",\"ability_id\":\"a\",\"source\":\"HEADER\"},"
                + "\"validation\":{\"outcome\":\"SUCCEEDED\",\"technique_id\":\"T1190\"},\"src_endpoint\":{\"ip\":\"1.2.3.4\"},"
                + "\"http_request\":{\"url\":{\"path\":\"/api/unmapped\"}}}";
        List<AttackEvent> events = new GtLogReader(() -> line).read(WINDOW_START, WINDOW_END);
        assertEquals(1, events.size());
        assertEquals(ScenarioMapping.UNKNOWN, events.get(0).scenario());
    }
}
