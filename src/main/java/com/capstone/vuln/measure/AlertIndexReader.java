package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.CorrelationSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * 인덱서 alert 검색 응답 → AlertEvent 리스트 (수집기 2).
 *
 * <p>S3-2 특이필드(실측): 앱 이벤트는 _source.data.* 아래, alert IP=data.src_endpoint.ip,
 * 문자열 "null"→null({@link MeasureJson}), timestamp 는 +0000(콜론 없음), searchableTime nullable.
 */
public class AlertIndexReader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Wazuh timestamp: 2026-10-16T10:35:05.609+0000 (오프셋 콜론 없음 → XX) */
    private static final DateTimeFormatter WAZUH_TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXX");

    private final AlertSearchSource source;
    /** R14 a: rule.id = 86601(Suricata alert) 질의 — 없으면 readNids 는 빈 목록 */
    private final AlertSearchSource nidsSource;

    public AlertIndexReader(AlertSearchSource source) {
        this(source, null);
    }

    public AlertIndexReader(AlertSearchSource source, AlertSearchSource nidsSource) {
        this.source = source;
        this.nidsSource = nidsSource;
    }

    /**
     * R14 a: rule.id 86601 alert → NidsAlert. 필드(실측, design-check C1): data.alert.signature_id(문자열),
     * data.flow_id(실수 문자열 '578501012733101.000000' — 소수부 ≠ 0 이면 null), data.tx_id(문자열), data.src_ip.
     * 응답의 hits.total 이 받은 수보다 많으면(검색 상한) 일부만 읽은 것이므로 측정 실패로 멈춘다.
     */
    public List<NidsAlert> readNids(Instant windowStart, Instant windowEndInclusive) {
        if (nidsSource == null) {
            return List.of();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(nidsSource.search(windowStart, windowEndInclusive));
        } catch (Exception e) {
            throw new IllegalStateException("NIDS alert 검색 응답 파싱 실패", e);
        }
        JsonNode hits = root.path("hits").path("hits");
        long total = root.path("hits").path("total").path("value").asLong(hits.size());
        if (total > hits.size()) {
            throw new IllegalStateException("NIDS alert " + total + "건 중 " + hits.size()
                    + "건만 받음 — 검색 상한 초과, 측정 실패(창을 나누거나 size 를 올릴 것)");
        }
        List<NidsAlert> alerts = new ArrayList<>();
        for (JsonNode hit : hits) {
            JsonNode s = hit.path("_source");
            Instant alertTime = parseTs(text(s.path("timestamp")));
            String sid = text(s.path("data").path("alert").path("signature_id"));
            if (alertTime == null || sid == null) {
                continue;
            }
            JsonNode d = s.path("data");
            alerts.add(new NidsAlert(Integer.parseInt(sid), alertTime, parseTs(text(s.path("searchableTime"))),
                    integral(text(d.path("flow_id"))), integral(text(d.path("tx_id"))), text(d.path("src_ip"))));
        }
        return alerts;
    }

    /** "578501012733101.000000" → 578501012733101, 소수부가 0 이 아니거나 숫자가 아니면 null */
    private static Long integral(String value) {
        if (value == null) {
            return null;
        }
        try {
            BigDecimal d = new BigDecimal(value);
            return d.signum() == 0 || d.stripTrailingZeros().scale() <= 0 ? d.longValueExact() : null;
        } catch (NumberFormatException | ArithmeticException e) {
            return null;
        }
    }

    public List<AlertEvent> read(Instant windowStart, Instant windowEndInclusive) {
        JsonNode root;
        try {
            root = MAPPER.readTree(source.search(windowStart, windowEndInclusive));
        } catch (Exception e) {
            throw new IllegalStateException("alert 검색 응답 파싱 실패", e);
        }

        List<AlertEvent> alerts = new ArrayList<>();
        for (JsonNode hit : root.path("hits").path("hits")) {
            JsonNode s = hit.path("_source");
            Instant alertTime = parseTs(text(s.path("timestamp")));
            if (alertTime == null) {
                continue;
            }
            String ruleId = text(s.path("rule").path("id"));
            JsonNode d = s.path("data");
            JsonNode correlation = d.path("correlation");
            JsonNode request = d.path("http_request");

            alerts.add(new AlertEvent(
                    ruleId,
                    text(d.path("validation").path("technique_id")),
                    alertTime,
                    parseTs(text(s.path("searchableTime"))), // nullable
                    text(d.path("rid")),
                    text(correlation.path("op_id")),
                    text(correlation.path("ability_id")),
                    text(d.path("src_endpoint").path("ip")),
                    text(request.path("url").path("path")),
                    parseSource(text(correlation.path("source"))),
                    MeasureJson.normalize(AlertEvent.usernameFromArgs(text(request.path("args"))))));
        }
        return alerts;
    }

    private static Instant parseTs(String value) {
        if (value == null) {
            return null;
        }
        return OffsetDateTime.parse(value, WAZUH_TS).toInstant();
    }

    /** data.correlation.source → CorrelationSource. 누락/미지정/알 수 없는 값은 NONE. */
    private static CorrelationSource parseSource(String value) {
        if (value == null) {
            return CorrelationSource.NONE;
        }
        try {
            return CorrelationSource.valueOf(value);
        } catch (IllegalArgumentException e) {
            return CorrelationSource.NONE;
        }
    }
}
