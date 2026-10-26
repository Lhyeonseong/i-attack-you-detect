package com.capstone.vuln.measure;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * 앱 OCSF 로그(attack.json.log) ↔ 정상 코퍼스 요청 1:1 대조 (ADR-S4-01 v1.8 R17 c).
 *
 * <p>응답에 rid 가 없으므로(S4-5 C1) Caldera 헤더 없는 줄(correlation.op_id 없음)만 보고, 전송 순서대로
 * path·args 가 같고 time 이 [전송 − 허용오차, 응답 + 허용오차] 안인 가장 이른 미사용 줄을 그 요청의 줄로 정한다.
 * 순차 전송이라 요청 창이 겹치지 않는다. 창 안 Caldera 헤더 없는 줄 중 대조되지 않은 줄 수도 센다(기록).
 */
public class BenignLogReader {

    /** 같은 호스트 시계 기준 — 앱 time 은 컨트롤러 진입 시각(전송~응답 사이) */
    public static final Duration TOLERANCE = Duration.ofMillis(50);

    public record Match(Map<Integer, String> ridBySeq, int unmatchedUntaggedLines) {
    }

    private record Line(Instant time, String rid, String path, String args) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AttackLogSource source;

    public BenignLogReader(AttackLogSource source) {
        this.source = source;
    }

    public Match match(List<BenignSent> sent) {
        if (sent.isEmpty()) {
            return new Match(Map.of(), 0);
        }
        Instant from = sent.get(0).sentAt().minus(TOLERANCE);
        Instant to = sent.get(sent.size() - 1).respondedAt().plus(TOLERANCE);
        List<Line> lines = untaggedLines(from, to);
        boolean[] used = new boolean[lines.size()];
        Map<Integer, String> rids = new LinkedHashMap<>();
        int cursor = 0;
        for (BenignSent s : sent) {
            Instant lo = s.sentAt().minus(TOLERANCE);
            Instant hi = s.respondedAt().plus(TOLERANCE);
            for (int i = cursor; i < lines.size(); i++) {
                Line l = lines.get(i);
                if (l.time().isAfter(hi)) {
                    break;
                }
                if (used[i] || l.time().isBefore(lo) || !s.endpoint().equals(l.path()) || !s.appArgs().equals(l.args())) {
                    continue;
                }
                used[i] = true;
                rids.put(s.seq(), l.rid());
                cursor = i + 1;
                break;
            }
        }
        int unmatched = 0;
        for (boolean u : used) {
            unmatched += u ? 0 : 1;
        }
        return new Match(rids, unmatched);
    }

    private List<Line> untaggedLines(Instant from, Instant to) {
        List<Line> out = new ArrayList<>();
        for (String raw : source.read().split("\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            JsonNode o;
            try {
                o = MAPPER.readTree(line);
            } catch (Exception e) {
                continue;
            }
            if (!o.path("time").canConvertToLong() || text(o.path("correlation").path("op_id")) != null) {
                continue; // Caldera 태깅 줄은 정상 코퍼스가 아니다(R17 b)
            }
            Instant t = Instant.ofEpochMilli(o.path("time").asLong());
            String rid = text(o.path("rid"));
            if (t.isBefore(from) || t.isAfter(to) || rid == null) {
                continue;
            }
            JsonNode req = o.path("http_request");
            out.add(new Line(t, rid, text(req.path("url").path("path")), text(req.path("args"))));
        }
        out.sort(Comparator.comparing(Line::time));
        return out;
    }
}
