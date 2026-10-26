package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * T5 — validation.v_metric_correlation (M05 source 분포) · v_metric_h2 (H2 판정, ALL 만).
 * 대상 = 멤버 correlation 에 detection_link ≥1 인 ATTACK 시도(UNCERTAIN 포함, R2 예외).
 * best source = 멤버 correlation.correlation_source 중 최고 순위(RID > HEADER > UA_FALLBACK > NONE)
 * — 멤버가 여럿(스프레이)이면 그중 최고.
 * H2 경계값 출처: V3 독립 검증된 wilson_ci 출력(0/73 hi 0.049992 는 V3 증거 파일
 * detections/measurements/evidence/2026-10-18_s4-2-crosscheck.log), statsmodels 0.15.0 일치(현성 측 2026-10-19).
 * 허용오차 1e-5.
 */
class CorrelationViewTest extends ValidationDbFixture {

    private static final double TOL = 1e-5;

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    private static Map<String, Object> dist(UUID run, String kind, String unit, String source) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_correlation WHERE run_id = ? AND split_kind = ? "
                + "AND split_unit = ? AND source = ?", run, kind, unit, source);
    }

    private static Map<String, Object> h2(UUID run) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_h2 WHERE run_id = ?", run);
    }

    /** A: RID 5(그중 1건은 멤버 3개 — 링크 없음·TIME_ONLY·RID)·HEADER 1·UA_FALLBACK 1·NONE 1(UNCERTAIN) + 제외 대상 */
    private static UUID runA() {
        return new MetricFixture(JDBC)
                .add(4, a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links(null, "NONE", "RID"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("HEADER"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("UA_FALLBACK"))
                .add(a("SQLI", "T1190", "UNCERTAIN").links("NONE"))
                // 제외: 멤버 없음 / 멤버는 있으나 링크 없음 / CONTROL
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED").links((String) null))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID").control())
                .close(MetricFixture.Close.VALID);
    }

    @Test
    void distributionOfBestSourceOverLinkedAttempts() {
        UUID run = runA();
        assertEquals("5/8", xn(dist(run, "ALL", "ALL", "RID")));
        assertEquals("1/8", xn(dist(run, "ALL", "ALL", "HEADER")));
        assertEquals("1/8", xn(dist(run, "ALL", "ALL", "UA_FALLBACK")));
        assertEquals("1/8", xn(dist(run, "ALL", "ALL", "NONE")));
        assertEquals("5/8", xn(dist(run, "SCENARIO", "SQLI", "RID")));

        Map<String, Object> ssrf = dist(run, "SCENARIO", "SSRF", "RID");
        assertEquals("0/0", xn(ssrf));
        assertEquals("NO_DATA", ssrf.get("status"));
        assertNull(ssrf.get("p"));

        Map<String, Object> rid = dist(run, "ALL", "ALL", "RID");
        Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(5, 8)");
        for (String k : List.of("p", "lo", "hi")) {
            assertEquals(d(ci, k), d(rid, k), 1e-12, k);
        }
        assertEquals(MetricFixture.DEF_VERSION, rid.get("definition_version"));
        // ALL + 시나리오 4종(UNKNOWN 시도 없음) × source 4종
        assertEquals(20, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_correlation WHERE run_id = ?",
                Integer.class, run));
    }

    @Test
    void h2InconclusiveBelow73() {
        Map<String, Object> row = h2(runA());
        assertEquals(8L, l(row, "n"));
        assertEquals(6L, l(row, "rid_header_x"));
        assertEquals(1L, l(row, "none_x"));
        assertEquals("INCONCLUSIVE", row.get("h2_status"));
    }

    @Test
    void h2PassAt73AllRid() {
        UUID run = new MetricFixture(JDBC)
                .add(73, a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .close(MetricFixture.Close.VALID);
        Map<String, Object> row = h2(run);
        assertEquals(73L, l(row, "n"));
        assertEquals(73L, l(row, "rid_header_x"));
        assertEquals(0.950008, d(row, "rid_header_lo"), TOL);
        assertEquals(0L, l(row, "none_x"));
        assertEquals(0.049992, d(row, "none_hi"), TOL);
        assertEquals("PASS", row.get("h2_status"));
        assertEquals(MetricFixture.DEF_VERSION, row.get("definition_version"));
    }

    @Test
    void h2FailWhenNoneUpperBoundAbove5Percent() {
        UUID run = new MetricFixture(JDBC)
                .add(72, a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .add(a("SQLI", "T1190", "UNCERTAIN").links("NONE"))
                .close(MetricFixture.Close.VALID);
        Map<String, Object> row = h2(run);
        assertEquals(73L, l(row, "n"));
        assertEquals(0.926403, d(row, "rid_header_lo"), TOL);
        assertEquals(0.073597, d(row, "none_hi"), TOL);
        assertEquals("FAIL", row.get("h2_status"));
    }

    /** R2 예외: 링크 있는 UNCERTAIN 시도 1건도 M05 분모에 들어간다 */
    @Test
    void linkedUncertainAttemptIsCounted() {
        UUID run = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "UNCERTAIN").links("RID"))
                .close(MetricFixture.Close.VALID);
        assertEquals("1/1", xn(dist(run, "ALL", "ALL", "RID")));
        assertEquals(1L, l(h2(run), "n"));
    }
}
