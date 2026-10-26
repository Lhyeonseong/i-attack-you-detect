package com.capstone.vuln.measure;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * BENIGN run 창의 알림 읽기 (ADR-S4-01 v1.8 R18 c). 창이 길어(정상 요청 수백 건) 한 번의 검색 상한(size 2000)을
 * 넘을 수 있으므로 겹치지 않는 조각 [t, t + chunk − 1 ms] 로 나눠 읽고, 조각마다 hits.total 이 받은 수보다 크거나
 * 정확한 수가 아니면(relation ≠ eq) 측정 실패로 멈춘다.
 * - 앱 로그 룰: vuln-webapp 그룹 질의(기존 IndexerAlertSearchSource) → rule.id·data.rid·timestamp
 * - NIDS: rule.id 86601 질의 → signature_id·timestamp(Wazuh)·data.timestamp(eve)·data.http.url·src/dest ip
 */
public class BenignAlertReader {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final DateTimeFormatter WAZUH_TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXX");

    private final AlertSearchSource appSource;
    private final AlertSearchSource nidsSource;
    private final Duration chunk;

    public BenignAlertReader(AlertSearchSource appSource, AlertSearchSource nidsSource, Duration chunk) {
        this.appSource = appSource;
        this.nidsSource = nidsSource;
        this.chunk = chunk;
    }

    public List<BenignAppAlert> readApp(Instant from, Instant to) {
        return read(appSource, from, to, s -> {
            Instant t = wazuhTs(text(s.path("timestamp")));
            String rule = text(s.path("rule").path("id"));
            return t == null || rule == null ? null : new BenignAppAlert(rule, text(s.path("data").path("rid")), t);
        });
    }

    public List<BenignNidsAlert> readNids(Instant from, Instant to) {
        return read(nidsSource, from, to, s -> {
            JsonNode d = s.path("data");
            Instant t = wazuhTs(text(s.path("timestamp")));
            String sid = text(d.path("alert").path("signature_id"));
            if (t == null || sid == null) {
                return null;
            }
            return new BenignNidsAlert(Integer.parseInt(sid), t, EveTelemetryReader.parseTs(text(d.path("timestamp"))),
                    text(d.path("http").path("url")), text(d.path("src_ip")), text(d.path("dest_ip")));
        });
    }

    private <T> List<T> read(AlertSearchSource source, Instant from, Instant to, Function<JsonNode, T> parse) {
        List<T> out = new ArrayList<>();
        for (Instant start = from; !start.isAfter(to); start = start.plus(chunk)) {
            Instant end = start.plus(chunk).minusMillis(1);
            if (end.isAfter(to)) {
                end = to;
            }
            JsonNode root;
            try {
                root = MAPPER.readTree(source.search(start, end));
            } catch (Exception e) {
                throw new IllegalStateException("BENIGN alert 검색 응답 파싱 실패 [" + start + ", " + end + "]", e);
            }
            JsonNode hits = root.path("hits").path("hits");
            JsonNode total = root.path("hits").path("total");
            long count = total.path("value").asLong(-1);
            String relation = text(total.path("relation"));
            if (count > hits.size() || (relation != null && !"eq".equals(relation))) {
                throw new IllegalStateException("BENIGN alert " + count + "건 중 " + hits.size() + "건만 받음 ["
                        + start + ", " + end + "] — 검색 상한 초과, 측정 실패(조각을 줄일 것)");
            }
            for (JsonNode hit : hits) {
                T a = parse.apply(hit.path("_source"));
                if (a != null) {
                    out.add(a);
                }
            }
        }
        return out;
    }

    private static Instant wazuhTs(String value) {
        return value == null ? null : OffsetDateTime.parse(value, WAZUH_TS).toInstant();
    }
}
