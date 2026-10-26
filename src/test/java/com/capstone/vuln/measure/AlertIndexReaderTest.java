package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.CorrelationSource;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AlertIndexReaderTest {

    // hit1: 정상 BF 실패 alert. hit2: src_endpoint.ip 가 문자열 "null", source "NONE", searchableTime 없음
    private static final String SAMPLE = """
            {"hits":{"hits":[
              {"_source":{
                "timestamp":"2026-10-16T10:35:05.609+0000",
                "rule":{"id":"100230"},
                "data":{"rid":"rid-bf","correlation":{"op_id":"mcukpa","ability_id":"7aa89a87","source":"HEADER"},
                        "src_endpoint":{"ip":"172.20.0.1"},"validation":{"technique_id":"T1110"},
                        "http_request":{"url":{"path":"/api/auth/login"},"args":"username=user1"}}}},
              {"_source":{
                "timestamp":"2026-10-16T10:35:06.100+0000",
                "rule":{"id":"100230"},
                "data":{"rid":"rid-x","correlation":{"op_id":"null","ability_id":"null","source":"NONE"},
                        "src_endpoint":{"ip":"null"},"validation":{"technique_id":"T1110"},
                        "http_request":{"url":{"path":"/api/auth/login"},"args":"username=null"}}}}
            ]}}""";

    private List<AlertEvent> read() {
        return new AlertIndexReader((from, to) -> SAMPLE)
                .read(Instant.parse("2026-10-16T10:30:00Z"), Instant.parse("2026-10-16T10:40:00Z"));
    }

    @Test
    void parses_timestamp_offset_without_colon_and_core_fields() {
        AlertEvent a = read().get(0);
        assertEquals(Instant.parse("2026-10-16T10:35:05.609Z"), a.alertTime()); // +0000 (콜론 없음) 파싱
        assertEquals("100230", a.ruleId());
        assertEquals("rid-bf", a.rid());
        assertEquals("mcukpa", a.opId());             // data.correlation.op_id (=paw)
        assertEquals("7aa89a87", a.abilityId());
        assertEquals("172.20.0.1", a.srcIp());        // data.src_endpoint.ip
        assertEquals("T1110", a.technique());
        assertEquals("user1", a.username());
        assertEquals(CorrelationSource.HEADER, a.idSource());
        assertNull(a.searchableTime());               // 없으면 null
    }

    @Test
    void string_null_becomes_java_null_and_source_none() {
        AlertEvent a = read().get(1);
        assertNull(a.srcIp());        // 문자열 "null" → null
        assertNull(a.opId());         // "null" → null
        assertNull(a.username());     // args username=null → null
        assertEquals(CorrelationSource.NONE, a.idSource());
    }

    @Test
    void returns_all_hits() {
        assertEquals(2, read().size());
    }
}
