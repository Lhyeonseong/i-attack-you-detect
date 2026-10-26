package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** T3 — validation.metric_scope: ADR-S4-01 R12 고정 범위 6행 + v1.7 R16 통제 목록 CONTROL 3행 (V6) */
class MetricScopeTest extends ValidationDbFixture {

    @Test
    void scopeIsExactlyTwoTechniquesAndFourScenarios() {
        Set<String> rows = JDBC.queryForList("SELECT kind || ':' || unit FROM validation.metric_scope", String.class)
                .stream().collect(Collectors.toSet());
        assertEquals(Set.of(
                "TECHNIQUE:T1190", "TECHNIQUE:T1110",
                "SCENARIO:SQLI", "SCENARIO:PATH_TRAVERSAL", "SCENARIO:BRUTE_FORCE", "SCENARIO:SSRF",
                "CONTROL:APP_RULE", "CONTROL:NIDS", "CONTROL:BACKEND_CORR"), rows);
        assertEquals(9, JDBC.queryForObject("SELECT count(*) FROM validation.metric_scope", Integer.class));
    }
}
