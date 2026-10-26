package com.capstone.vuln.measure;

import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 게이트 리포트 출력 — 사람이 읽는 표(.md)와 기계가 읽는 수치(.json)를 같은 timestamp stem 으로 쓴다.
 * 파일명 timestamp 는 ':' 를 '-' 로 치환(파일시스템 안전).
 */
public class GateReportWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 리포트 2개(.md/.json)를 dir 아래 쓰고 .md 경로를 반환. */
    public Path write(GateReport report, Path dir) {
        try {
            Files.createDirectories(dir);
            String stem = "gate-report-" + report.generatedAt().toString()
                    .replace(":", "-").replace(".", "-");
            Path md = dir.resolve(stem + ".md");
            Path json = dir.resolve(stem + ".json");
            Files.writeString(md, markdown(report), StandardCharsets.UTF_8);
            Files.writeString(json, json(report), StandardCharsets.UTF_8);
            return md;
        } catch (IOException e) {
            throw new UncheckedIOException("게이트 리포트 쓰기 실패", e);
        }
    }

    public static String markdown(GateReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("# S3-5b Gate Report\n\n");
        sb.append("- generated: ").append(r.generatedAt()).append('\n');
        sb.append("- overall: **").append(r.overall()).append("**\n");
        sb.append("- total conclusive samples: ").append(r.totalSamples())
                .append(" | uncertain: ").append(r.totalUncertain()).append("\n\n");
        sb.append("| scenario | samples | matchRate | overestimate | uncertain | uncertainRate | result |\n");
        sb.append("|---|---:|---:|---:|---:|---:|---|\n");
        for (ScenarioGate g : r.scenarios()) {
            sb.append(String.format("| %s | %d | %.3f | %d | %d | %.3f | %s |%n",
                    g.scenario(), g.samples(), g.matchRate(), g.overestimateCount(),
                    g.uncertainCount(), g.uncertainRate(), g.result()));
        }
        sb.append("\n_gate: conclusive≥").append(GateEvaluator.MIN_CONCLUSIVE_SAMPLES)
                .append(" & matchRate≥").append(GateEvaluator.MIN_MATCH_RATE)
                .append(" & overestimate==0 → PASS; samples<20 → INCONCLUSIVE; else FAIL_\n");
        return sb.toString();
    }

    public static String json(GateReport r) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("generatedAt", r.generatedAt().toString());
        root.put("overall", r.overall().name());
        root.put("totalSamples", r.totalSamples());
        root.put("totalUncertain", r.totalUncertain());
        // Map.of 는 순서를 보장하지 않아 run 마다 키 순서가 달라졌다 — 재현성을 위해 순서 고정
        Map<String, Object> thresholds = new LinkedHashMap<>();
        thresholds.put("minConclusiveSamples", GateEvaluator.MIN_CONCLUSIVE_SAMPLES);
        thresholds.put("minMatchRate", GateEvaluator.MIN_MATCH_RATE);
        thresholds.put("maxOverestimate", 0);
        root.put("thresholds", thresholds);
        List<Map<String, Object>> scenarios = new ArrayList<>();
        for (ScenarioGate g : r.scenarios()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("scenario", g.scenario());
            m.put("samples", g.samples());
            m.put("matchRate", g.matchRate());
            m.put("overestimateCount", g.overestimateCount());
            m.put("uncertainCount", g.uncertainCount());
            m.put("uncertainRate", g.uncertainRate());
            m.put("result", g.result().name());
            scenarios.add(m);
        }
        root.put("scenarios", scenarios);
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("게이트 리포트 JSON 직렬화 실패", e);
        }
    }
}
