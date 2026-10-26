package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackScenario;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T7 전제 고정 (ADR-S4-01 v1.4 D6): ScenarioMapping 이 낼 수 있는 값 ⊆ metric_scope SCENARIO 4종 ∪ {UNKNOWN}.
 * 이 전제에서만 V4 의 UNKNOWN 매핑(NULL·범위 밖 → UNKNOWN)과 GateEvaluator 의 시나리오 묶음(NULL → UNKNOWN)이 같다.
 * SCOPE 는 V3__metric_foundation.sql metric_scope 시드(R12)와 같아야 한다 — 목록 변경은 ADR 개정으로만.
 */
class ScenarioMappingScopeTest {

    private static final Set<String> SCOPE = Set.of("SQLI", "PATH_TRAVERSAL", "BRUTE_FORCE", "SSRF");

    /** scenarioFor 는 AttackScenario.name() 또는 UNKNOWN 만 반환한다 — enum 전체가 범위 안이면 반환값도 범위 안 */
    @Test
    void everyAttackScenarioIsInMetricScope() {
        assertEquals(SCOPE, Set.copyOf(Arrays.stream(AttackScenario.values()).map(Enum::name).toList()));
    }

    @Test
    void returnedValuesAreScopeOrUnknown() {
        List<String> paths = Arrays.asList("/api/products/search", "/api/files/download", "/api/preview",
                "/api/auth/login", "/api/unregistered", "", null);
        for (String path : paths) {
            String scenario = ScenarioMapping.scenarioFor(path);
            assertTrue(SCOPE.contains(scenario) || ScenarioMapping.UNKNOWN.equals(scenario), path + " → " + scenario);
        }
        assertEquals("UNKNOWN", ScenarioMapping.UNKNOWN);
        assertEquals(ScenarioMapping.UNKNOWN, ScenarioMapping.scenarioFor(null));
        assertEquals(ScenarioMapping.UNKNOWN, ScenarioMapping.scenarioFor("/api/unregistered"));
    }
}
