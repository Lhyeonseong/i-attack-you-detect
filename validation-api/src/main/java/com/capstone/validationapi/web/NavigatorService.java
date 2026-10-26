package com.capstone.validationapi.web;

import com.capstone.validationapi.dto.ApiDtos.Rate;
import com.capstone.validationapi.dto.ApiDtos.Snapshot;
import com.capstone.validationapi.repo.ValidationRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * ATT&CK Navigator 레이어(ADR-S4-02 D4·ADR-S4-04 화면⑤).
 * versions: layer 4.5 · attack 20.0 · navigator 5.3.2(Step1 결정, import 실패 시 5.0.0).
 * score 0~100, n=0 인 기법은 생략. 측정 범위 기법 = T1190(SQLI·PT·SSRF)·T1110(BRUTE_FORCE).
 */
@Service
public class NavigatorService {

    private static final Map<String, String> SCENARIO_TECHNIQUE = Map.of(
            "SQLI", "T1190", "PATH_TRAVERSAL", "T1190", "SSRF", "T1190", "BRUTE_FORCE", "T1110");

    private final ValidationRepository repo;

    public NavigatorService(ValidationRepository repo) {
        this.repo = repo;
    }

    public Map<String, Object> layer(UUID runId, String kind, String definitionVersion) {
        List<Map<String, Object>> techniques = switch (kind) {
            case "detection" -> detectionTechniques(runId);
            case "visibility" -> visibilityTechniques(runId, definitionVersion);
            default -> throw new IllegalArgumentException("layer 는 detection|visibility 만");
        };
        Map<String, Object> versions = new LinkedHashMap<>();
        versions.put("attack", "20.0");
        versions.put("navigator", "5.3.2");
        versions.put("layer", "4.5");

        Map<String, Object> layer = new LinkedHashMap<>();
        layer.put("name", "validation-" + kind);
        layer.put("versions", versions);
        layer.put("domain", "enterprise-attack");
        layer.put("description", "S4-6 검증 측정 " + kind + " (run " + runId.toString().substring(0, 8) + ")");
        layer.put("techniques", techniques);
        layer.put("gradient", Map.of(
                "colors", List.of("#ff6666", "#ffe766", "#8ec843"),
                "minValue", 0, "maxValue", 100));
        return layer;
    }

    /** 탐지율: v_metric_rates M02(detected/all) TECHNIQUE scope. */
    private List<Map<String, Object>> detectionTechniques(UUID runId) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Rate r : repo.rates(runId)) {
            if (!"M02".equals(r.metricId()) || !"TECHNIQUE".equals(r.scopeKind())) {
                continue;
            }
            if (r.n() == null || r.n() == 0 || r.p() == null) {
                continue;   // n=0 생략
            }
            out.add(technique(r.scopeKey(), r.p() * 100.0, r.x() + "/" + r.n() + " 탐지"));
        }
        return out;
    }

    /** 가시성: 스냅샷 M07a(관측/시도) SCENARIO 를 기법으로 합산. */
    private List<Map<String, Object>> visibilityTechniques(UUID runId, String definitionVersion) {
        Map<String, long[]> perTech = new LinkedHashMap<>();   // tech -> [observed, total]
        for (Snapshot s : repo.snapshot(definitionVersion, runId)) {
            if (s.metricId() == null || !s.metricId().startsWith("M07a") || !"SCENARIO".equals(s.scopeKind())) {
                continue;
            }
            String tech = SCENARIO_TECHNIQUE.get(s.scopeKey());
            if (tech == null || s.n() == null || s.x() == null) {
                continue;
            }
            long[] agg = perTech.computeIfAbsent(tech, k -> new long[2]);
            agg[0] += s.x();
            agg[1] += s.n();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (var e : perTech.entrySet()) {
            long total = e.getValue()[1];
            if (total == 0) {
                continue;
            }
            double score = e.getValue()[0] * 100.0 / total;
            out.add(technique(e.getKey(), score, e.getValue()[0] + "/" + total + " 관측"));
        }
        return out;
    }

    private static Map<String, Object> technique(String id, double score, String comment) {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("techniqueID", id);
        t.put("score", Math.round(score * 10.0) / 10.0);
        t.put("comment", comment);
        t.put("enabled", true);
        return t;
    }
}
