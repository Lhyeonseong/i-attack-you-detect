package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static com.capstone.vuln.measure.MetricFixture.rate;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * T7·T8 — V6 지표 뷰 v_metric_m07a(R15)·v_metric_m13(R16), I2 시나리오별(R16), NIDS 수집 기록·sid 시드.
 * x/n 기대값은 픽스처를 손으로 센 값이다(각 테스트 주석).
 */
class NidsMetricViewTest extends ValidationDbFixture {

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    /**
     * 픽스처 N1 (NIDS 수집 run). 공격 시도 8건 + 대조 1건:
     *  SQLI a1 SD APP_RULE(100210) tel(1,1) / a2 SD NIDS(1000013) tel(1,1) /
     *       a3 SM tel(1,0) + 판정에 안 쓰이는 링크 2개(APP_RULE technique NULL, NIDS MARKER sid)
     *  PT   p1 SD APP_RULE(100220)+NIDS(1000020) tel(1,2) / p2 FAILED_UNSEEN tel(1,0)
     *  BF   b1 SD(BF_SEQUENCE DETECTED) APP_RULE(100230)+NIDS(1000031) tel(13,13)
     *  SSRF s1 SD APP_RULE(100240) tel(1,1) / s2 UNCERTAIN(링크 없음) tel(1,1) / 대조 1건 tel(1,1)
     */
    private static UUID n1() {
        return new MetricFixture(JDBC).nidsCollected()
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100210").telemetry(1, 1))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("NIDS", "1000013").telemetry(1, 1))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED").ctl("APP_RULE", "100002", null)
                        .ctl("NIDS", "1000001").telemetry(1, 0))
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100220")
                        .ctl("NIDS", "1000020").telemetry(1, 2))
                .add(a("PATH_TRAVERSAL", "T1190", "FAILED_UNSEEN").telemetry(1, 0))
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100230")
                        .ctl("NIDS", "1000031").telemetry(13, 13))
                .add(a("SSRF", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100240").telemetry(1, 1))
                .add(a("SSRF", "T1190", "UNCERTAIN").telemetry(1, 1))
                .add(a("SSRF", "T1190", "FAILED_UNSEEN").control().telemetry(1, 1))
                .close(MetricFixture.Close.VALID);
    }

    private static Map<String, Object> m07a(UUID run, String sensor, String kind, String unit) {
        return JDBC.queryForMap("""
                SELECT * FROM validation.v_metric_m07a
                WHERE run_id = ? AND metric_id = ? AND split_kind = ? AND split_unit = ?""",
                run, "M07a_" + sensor, kind, unit);
    }

    private static Map<String, Object> m13(UUID run, String control, String scenario) {
        return JDBC.queryForMap("""
                SELECT * FROM validation.v_metric_m13
                WHERE run_id = ? AND metric_id = ? AND split_kind = 'SCENARIO' AND split_unit = ?""",
                run, "M13_" + control, scenario);
    }

    private static void assertCell(Map<String, Object> row, String expectedXn, String status) {
        assertEquals(expectedXn, xn(row), row.toString());
        assertEquals(status, row.get("status"), row.toString());
        Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(?, ?)",
                l(row, "x"), l(row, "n"));
        if (l(row, "n") == 0) {
            assertNull(row.get("p"));
            return;
        }
        assertEquals(d(ci, "p"), d(row, "p"), 1e-12);
        assertEquals(d(ci, "lo"), d(row, "lo"), 1e-12);
        assertEquals(d(ci, "hi"), d(row, "hi"), 1e-12);
    }

    /** 0% 로 표기하면 안 되는 칸 — 분자·점추정·구간 NULL, 분모(S_ALL)는 남긴다 */
    private static void assertNoValue(Map<String, Object> row, long n, String status) {
        assertEquals(status, row.get("status"), row.toString());
        assertNull(row.get("x"), row.toString());
        assertNull(row.get("p"), row.toString());
        assertNull(row.get("lo"), row.toString());
        assertNull(row.get("hi"), row.toString());
        assertEquals(n, l(row, "n"), row.toString());
    }

    // ---- T7 M07a ----

    /** APP_LOG = 시도 원천이라 n/n, NIDS = eve http ≥ 1 인 시도 / 전체 시도(UNCERTAIN 포함, 대조 제외) */
    @Test
    void t7M07aAppLogIsStructurallyOneAndNidsIsTheLinkedHttpRatio() {
        UUID run = n1();

        assertCell(m07a(run, "APP_LOG", "ALL", "ALL"), "8/8", "OK");
        assertCell(m07a(run, "NIDS", "ALL", "ALL"), "6/8", "OK");
        assertCell(m07a(run, "APP_LOG", "SCENARIO", "SQLI"), "3/3", "OK");
        assertCell(m07a(run, "NIDS", "SCENARIO", "SQLI"), "2/3", "OK");
        assertCell(m07a(run, "NIDS", "SCENARIO", "PATH_TRAVERSAL"), "1/2", "OK");
        assertCell(m07a(run, "NIDS", "SCENARIO", "BRUTE_FORCE"), "1/1", "OK");
        assertCell(m07a(run, "NIDS", "SCENARIO", "SSRF"), "2/2", "OK");
        assertEquals("ADR-S4-01 v1.7", m07a(run, "NIDS", "ALL", "ALL").get("definition_version"));
        // 전체 + 시나리오 4 (UNKNOWN 없음) × 센서 2
        assertEquals(10, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m07a WHERE run_id = ?",
                Integer.class, run));
    }

    // ---- T7 M13 ----

    /**
     * 분모 = 시나리오 S_ALL (SQLI 3, PT 1, BF 1, SSRF 1). 판정에 안 쓰이는 링크(technique 불일치·MARKER sid)는 세지 않는다.
     * 룰 없음 'NO_RULE'·대상 아님 'NOT_APPLICABLE' 은 0% 가 아니라 값 없음.
     */
    @Test
    void t7M13ControlByScenarioWithNoRuleAndNotApplicable() {
        UUID run = n1();

        assertCell(m13(run, "APP_RULE", "SQLI"), "1/3", "OK");
        assertCell(m13(run, "APP_RULE", "PATH_TRAVERSAL"), "1/1", "OK");
        assertNoValue(m13(run, "APP_RULE", "BRUTE_FORCE"), 1, "NOT_APPLICABLE");
        assertCell(m13(run, "APP_RULE", "SSRF"), "1/1", "OK");

        assertCell(m13(run, "NIDS", "SQLI"), "1/3", "OK");
        assertCell(m13(run, "NIDS", "PATH_TRAVERSAL"), "1/1", "OK");
        assertCell(m13(run, "NIDS", "BRUTE_FORCE"), "1/1", "OK");
        assertCell(m13(run, "NIDS", "SSRF"), "0/1", "OK"); // ANALYTIC sid 가 있으니 측정된 0

        assertNoValue(m13(run, "BACKEND_CORR", "SQLI"), 3, "NO_RULE");
        assertNoValue(m13(run, "BACKEND_CORR", "PATH_TRAVERSAL"), 1, "NO_RULE");
        assertCell(m13(run, "BACKEND_CORR", "BRUTE_FORCE"), "1/1", "OK");
        assertNoValue(m13(run, "BACKEND_CORR", "SSRF"), 1, "NO_RULE");

        assertEquals(12, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m13 WHERE run_id = ?",
                Integer.class, run));
    }

    /** n = 0 시나리오는 NO_DATA (규칙 칸 NO_RULE·NOT_APPLICABLE 은 그대로) */
    @Test
    void t7M13EmptyScenarioIsNoData() {
        UUID run = new MetricFixture(JDBC).nidsCollected()
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_DETECTED").telemetry(13, 13))
                .close(MetricFixture.Close.VALID);

        assertCell(m13(run, "APP_RULE", "SQLI"), "0/0", "NO_DATA");
        assertCell(m13(run, "NIDS", "SQLI"), "0/0", "NO_DATA");
        assertNoValue(m13(run, "BACKEND_CORR", "SQLI"), 0, "NO_RULE");
        assertCell(m07a(run, "NIDS", "SCENARIO", "SQLI"), "0/0", "NO_DATA");
    }

    /** R14 이전 run(nids_window_stat 없음): NIDS·M07a 는 NOT_COLLECTED(값 없음), APP_RULE·BACKEND_CORR 는 계산 */
    @Test
    void runWithoutNidsCollectionIsNotCollectedInsteadOfZero() {
        UUID run = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100210"))
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_DETECTED"))
                .close(MetricFixture.Close.VALID);

        assertNoValue(m13(run, "NIDS", "SQLI"), 1, "NOT_COLLECTED");
        assertNoValue(m13(run, "NIDS", "BRUTE_FORCE"), 1, "NOT_COLLECTED");
        assertCell(m13(run, "APP_RULE", "SQLI"), "1/1", "OK");
        assertCell(m13(run, "BACKEND_CORR", "BRUTE_FORCE"), "1/1", "OK");
        assertNoValue(m07a(run, "APP_LOG", "ALL", "ALL"), 2, "NOT_COLLECTED");
        assertNoValue(m07a(run, "NIDS", "ALL", "ALL"), 2, "NOT_COLLECTED");
    }

    // ---- T8 I2 ----

    /** SQLi·PT·SSRF: (APP_RULE ∪ NIDS) x = M02 x, BF: BACKEND_CORR x = M02 x (시도 단위 뷰에서 합집합을 센다) */
    private static void assertI2(UUID run) {
        for (String scenario : List.of("SQLI", "PATH_TRAVERSAL", "BRUTE_FORCE", "SSRF")) {
            String union = "BRUTE_FORCE".equals(scenario) ? "backend_corr" : "(app_rule OR nids)";
            long unionX = JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m13_attempt "
                    + "WHERE run_id = ? AND scenario_unit = ? AND in_s_all AND " + union, Long.class, run, scenario);
            Map<String, Object> m02 = rate(JDBC, run, "M02", "SCENARIO", scenario);
            assertEquals(l(m02, "x"), unionX, scenario);
        }
    }

    @Test
    void t8I2HoldsPerScenarioOnFixtureN1() {
        UUID run = n1();
        assertI2(run);
        assertEquals("2/3", xn(rate(JDBC, run, "M02", "SCENARIO", "SQLI")));
    }

    /**
     * NIDS BF 알림만 있고 시퀀스 미성립(BF SUCCEEDED_MISSED): M13 NIDS×BF = 1/1 로 집계되지만 I2(BF = BACKEND_CORR)는 유지
     * — BACKEND_CORR×BF 0/1 = M02 BF 0/1.
     */
    @Test
    void t8BruteForceNidsOnlyWithoutSequenceKeepsI2() {
        UUID run = new MetricFixture(JDBC).nidsCollected()
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_MISSED").ctl("NIDS", "1000032").telemetry(13, 13))
                .close(MetricFixture.Close.VALID);

        assertCell(m13(run, "NIDS", "BRUTE_FORCE"), "1/1", "OK");
        assertCell(m13(run, "BACKEND_CORR", "BRUTE_FORCE"), "0/1", "OK");
        assertEquals("0/1", xn(rate(JDBC, run, "M02", "SCENARIO", "BRUTE_FORCE")));
        assertI2(run);
    }

    // ---- 기록 ----

    /** orphan(eve http 와 연결 안 된 86601) 은 op 창마다 기록되고 run 별로 합산된다 */
    @Test
    void orphanAlertsAreRecordedPerWindowAndSummedPerRun() {
        UUID run = com.capstone.vuln.correlation.TestRuns.openTestRun(JDBC);
        NidsWindowRepository repo = new NidsWindowRepository(DS);
        Instant t = Instant.parse("2026-10-21T10:00:00Z");
        repo.save(run, "op-1", t, t.plusSeconds(60), new NidsWindowCounts(100, 0, 9, 9, 13, 76, 0, 2, 20, 20));
        repo.save(run, "op-2", t.plusSeconds(200), t.plusSeconds(260),
                new NidsWindowCounts(101, 2, 10, 8, 13, 76, 0, 2, 20, 19));

        Map<String, Object> s = JDBC.queryForMap("SELECT * FROM validation.v_nids_run_stat WHERE run_id = ?", run);
        assertEquals(2L, l(s, "windows"));
        assertEquals(201L, l(s, "nids_alerts"));
        assertEquals(2L, l(s, "orphan_alerts"));
        assertEquals(17L, l(s, "analytic_linked"));
        assertEquals(39L, l(s, "http_attributed"));
        Timestamp start = JDBC.queryForObject("SELECT window_start FROM validation.nids_window_stat "
                + "WHERE run_id = ? AND op_id = 'op-1'", Timestamp.class, run);
        assertEquals(t, start.toInstant());
    }

    /** V6 nids_sid_class 시드 = NidsSidCatalog.V1_7 (ADR 분류표) */
    @Test
    void sidClassSeedMatchesCatalog() {
        Set<String> seeded = new HashSet<>(JDBC.queryForList(
                "SELECT sid || ':' || class || ':' || coalesce(scenario, '-') FROM validation.nids_sid_class",
                String.class));
        Set<String> catalog = new HashSet<>();
        NidsSidCatalog.V1_7.entries().forEach(e -> catalog.add(
                e.sid() + ":" + e.sidClass() + ":" + (e.scenario() == null ? "-" : e.scenario())));
        assertEquals(catalog, seeded);
        assertEquals(Set.of("1000018", "1000041"), new HashSet<>(JDBC.queryForList(
                "SELECT sid::text FROM validation.nids_sid_class WHERE class = 'UNDECIDED'", String.class)));
    }
}
