package com.capstone.validationapi;

import com.capstone.validationapi.support.AbstractApiIT;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ADR-S4-02 D4 계약·일관성·compare·navigator. 구간 값은 DB(wilson/newcombe) 그대로.
 * 숫자 단언은 JSON provider 의 수치 타입(Double/BigDecimal)에 의존하지 않도록 Number→double 로 비교(허용오차 ±0.0005).
 */
class ContractIT extends AbstractApiIT {

    private static final double EPS = 0.0005;

    @Autowired
    MockMvc mvc;

    private MockHttpServletRequestBuilder api(String path) {
        return get(path).header("Authorization", "Bearer " + BEARER);
    }

    private String body(String path) throws Exception {
        return mvc.perform(api(path)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    /** jsonPath 필터 결과(배열)의 첫 수치를 double 로. */
    private static double num(String json, String path) {
        Object o = JsonPath.read(json, path);
        if (o instanceof List<?> l) {
            assertTrue(!l.isEmpty(), "경로 결과 없음: " + path);
            o = l.get(0);
        }
        return ((Number) o).doubleValue();
    }

    private static long lng(String json, String path) {
        Object o = JsonPath.read(json, path);
        if (o instanceof List<?> l) {
            assertTrue(!l.isEmpty(), "경로 결과 없음: " + path);
            o = l.get(0);
        }
        return ((Number) o).longValue();
    }

    @Test
    void metaHasVersionsAndNavigator() throws Exception {
        mvc.perform(api("/api/v1/meta"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.definition_versions", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$.run_count", greaterThanOrEqualTo(2)))
                .andExpect(jsonPath("$.navigator.layer").value("4.5"))
                .andExpect(jsonPath("$.navigator.attack").value("20.0"))
                .andExpect(jsonPath("$.navigator.navigator").value("5.3.2"));
    }

    @Test
    void runDetailHasExpectedCounts() throws Exception {
        // 대조(control) 건수 원천: /runs/{id} expected_controls (대시보드 '대조 20')
        mvc.perform(api("/api/v1/runs/" + AFTER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expected_attempts").value(140))
                .andExpect(jsonPath("$.expected_controls").value(20));
    }

    // ── 픽스처 기대값(Wilson, z=1.959964) ───────────────────────────────────────
    @Test
    void afterRatesM02All_140of140_97_3to100() throws Exception {
        String j = body("/api/v1/runs/" + AFTER + "/metrics/rates");
        String f = "$[?(@.metric_id=='M02' && @.scope_kind=='ALL')]";
        assertEquals(140, lng(j, f + ".x"));
        assertEquals(140, lng(j, f + ".n"));
        assertEquals(1.0, num(j, f + ".p"), EPS);
        assertEquals(0.973, num(j, f + ".lo"), EPS);   // Wilson 140/140 하한
        assertEquals(1.0, num(j, f + ".hi"), EPS);
    }

    @Test
    void afterRatesM02SqliScenario_20of20_lower83_9() throws Exception {
        String j = body("/api/v1/runs/" + AFTER + "/metrics/rates");
        String f = "$[?(@.metric_id=='M02' && @.scope_kind=='SCENARIO' && @.scope_key=='SQLI')]";
        assertEquals(20, lng(j, f + ".n"));
        assertEquals(0.839, num(j, f + ".lo"), EPS);
    }

    @Test
    void beforeRatesM02All_120of140_85_7() throws Exception {
        String j = body("/api/v1/runs/" + BEFORE + "/metrics/rates");
        String f = "$[?(@.metric_id=='M02' && @.scope_kind=='ALL')]";
        assertEquals(120, lng(j, f + ".x"));
        assertEquals(140, lng(j, f + ".n"));
        assertEquals(0.790, num(j, f + ".lo"), EPS);
        assertEquals(0.906, num(j, f + ".hi"), EPS);
    }

    @Test
    void nZeroMetricHasNullInterval() throws Exception {
        // correlation 은 detection_link 미적재 → n=0 → p·lo·hi null (ADR n=0 규칙)
        mvc.perform(api("/api/v1/runs/" + AFTER + "/metrics/correlation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.n==0)].p", hasItem(nullValue())));
    }

    // ── 비-VALID·404·400 ────────────────────────────────────────────────────────
    @Test
    void invalidRunMetricsReturns409() throws Exception {
        mvc.perform(api("/api/v1/runs/" + INVALID_RUN + "/metrics/rates")).andExpect(status().isConflict());
    }

    @Test
    void absentRunMetricsReturns404() throws Exception {
        mvc.perform(api("/api/v1/runs/" + UUID.randomUUID() + "/metrics/rates")).andExpect(status().isNotFound());
    }

    @Test
    void unknownMetricNameReturns400() throws Exception {
        mvc.perform(api("/api/v1/runs/" + AFTER + "/metrics/bogus")).andExpect(status().isBadRequest());
    }

    @Test
    void badVerdictFilterReturns400() throws Exception {
        mvc.perform(api("/api/v1/runs/" + AFTER + "/attempts").param("verdict", "BOGUS"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void limitOverMaxReturns400() throws Exception {
        mvc.perform(api("/api/v1/runs/" + AFTER + "/attempts").param("limit", "99999"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void badUuidReturns400() throws Exception {
        mvc.perform(api("/api/v1/runs/not-a-uuid/metrics/rates")).andExpect(status().isBadRequest());
    }

    // ── 일관성: 스냅샷 == 라이브 ──────────────────────────────────────────────────
    @Test
    void snapshotMatchesLiveForM02All() throws Exception {
        String snap = body("/api/v1/snapshot?run_id=" + AFTER);
        String live = body("/api/v1/runs/" + AFTER + "/metrics/rates");
        String f = "$[?(@.metric_id=='M02' && @.scope_kind=='ALL')]";
        assertEquals(lng(live, f + ".x"), lng(snap, f + ".x"));
        assertEquals(lng(live, f + ".n"), lng(snap, f + ".n"));
        assertEquals(num(live, f + ".p"), num(snap, f + ".p"), EPS);
    }

    // ── compare ──────────────────────────────────────────────────────────────────
    @Test
    void compareSqliMissedRateMinus1_000() throws Exception {
        // M03(놓침률) SCENARIO SQLI: before 20/20 → after 0/20, diff = after−before = −1.000 [−1.000,−0.772]
        String j = mvc.perform(api("/api/v1/compare?before=" + BEFORE + "&after=" + AFTER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.shared_definition_versions", hasSize(greaterThanOrEqualTo(1))))
                .andReturn().getResponse().getContentAsString();
        String f = "$.rows[?(@.metric_id=='M03' && @.scope_kind=='SCENARIO' && @.scope_key=='SQLI')]";
        assertEquals(-1.0, num(j, f + ".diff"), EPS);
        assertEquals(-1.0, num(j, f + ".lo"), EPS);
        assertEquals(-0.772, num(j, f + ".hi"), EPS);
    }

    @Test
    void compareWithNoSharedDefinitionReturns409() throws Exception {
        mvc.perform(api("/api/v1/compare?before=" + AFTER + "&after=" + INVALID_RUN))
                .andExpect(status().isConflict());
    }

    // ── navigator ──────────────────────────────────────────────────────────────
    @Test
    void navigatorLayerStructure() throws Exception {
        String j = body("/api/v1/navigator-layer?run_id=" + AFTER + "&layer=detection");
        assertEquals("4.5", JsonPath.read(j, "$.versions.layer"));
        assertEquals("20.0", JsonPath.read(j, "$.versions.attack"));
        assertEquals("enterprise-attack", JsonPath.read(j, "$.domain"));
        List<?> techs = JsonPath.read(j, "$.techniques");
        assertTrue(!techs.isEmpty(), "techniques 비어있음");
        double score = num(j, "$.techniques[0].score");
        assertTrue(score >= 0.0 && score <= 100.0, "score 0~100: " + score);
    }

    @Test
    void navigatorBadLayerReturns400() throws Exception {
        mvc.perform(api("/api/v1/navigator-layer?run_id=" + AFTER + "&layer=bogus"))
                .andExpect(status().isBadRequest());
    }
}
