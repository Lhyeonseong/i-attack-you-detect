package com.capstone.vuln.measure;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * Suricata eve.json → 창 안 http 이벤트 (ADR-S4-01 v1.7 R14 b·c, 수집기 4).
 *
 * <p>읽기 방식은 attack.json.log 와 같다(docker compose exec cat, 읽기 전용 — 파일 수정·로테이트 없음).
 * eve.json 에는 바이너리 바이트가 섞인 줄이 있어 JSON 파싱이 안 되는 줄은 건너뛴다.
 * timestamp 는 마이크로초 + "+0000"(콜론 없음) 형식이다.
 */
public class EveTelemetryReader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AttackLogSource source;

    public EveTelemetryReader(AttackLogSource source) {
        this.source = source;
    }

    public List<EveHttp> read(Instant fromInclusive, Instant toInclusive) {
        List<EveHttp> out = new ArrayList<>();
        for (String raw : source.read().split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || !line.contains("\"event_type\":\"http\"")) {
                continue;
            }
            JsonNode o;
            try {
                o = MAPPER.readTree(line);
            } catch (Exception e) {
                continue;
            }
            if (!"http".equals(text(o.path("event_type")))
                    || !o.path("flow_id").canConvertToLong() || !o.path("tx_id").canConvertToLong()) {
                continue;
            }
            Instant time = parseTs(text(o.path("timestamp")));
            if (time == null || time.isBefore(fromInclusive) || time.isAfter(toInclusive)) {
                continue;
            }
            JsonNode http = o.path("http");
            JsonNode port = o.path("dest_port");
            out.add(new EveHttp(o.path("flow_id").asLong(), o.path("tx_id").asLong(), time,
                    text(http.path("url")), text(http.path("http_user_agent")),
                    text(o.path("src_ip")), text(o.path("dest_ip")), port.canConvertToInt() ? port.asInt() : null));
        }
        return out;
    }

    /** 2026-10-21T10:03:46.211837+0000 → 오프셋에 콜론을 넣어 ISO 로 파싱 */
    static Instant parseTs(String value) {
        if (value == null) {
            return null;
        }
        String iso = value.matches(".*[+-]\\d{4}$")
                ? value.substring(0, value.length() - 2) + ":" + value.substring(value.length() - 2)
                : value;
        try {
            return OffsetDateTime.parse(iso).toInstant();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
