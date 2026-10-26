package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.TestRuns;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.d;
import static com.capstone.vuln.measure.MetricFixture.l;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S4-3 metric_snapshot (V5, ADR-S4-01 v1.6 R13) — 라이브 뷰(V4)와 별개인 불변 기록 층.
 *
 * <p>기대값은 V4 테스트의 손계산 값(F1: MetricRatesViewTest·MttdViewTest·CoverageViewTest·AttackerAccuracyViewTest,
 * 픽스처 A: CorrelationViewTest)과 crosscheck 증거(2026-10-18_s4-2-crosscheck.log 'wilson 20/20: lo=0.838875')를
 * 그대로 옮긴 것이다 — 여기서 새로 계산하지 않는다. 구간·백분위의 나머지 값은 "스냅샷 = 같은 run 의 라이브 뷰 값"
 * (V4 테스트가 wilson_ci·quantile_t8 와 대조해 둔 값)으로 본다.
 *
 * <p>스냅샷 행은 지울 수 없으므로 공유 컨테이너(ValidationDbFixture) 대신 이 클래스 전용 컨테이너를 쓴다.
 */
class MetricSnapshotTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final JdbcTemplate JDBC;
    /** 컨테이너 관리자(superuser) — 권한(REVOKE)을 우회해도 트리거가 막는지 본다 */
    private static final JdbcTemplate ADMIN;

    static {
        PG.start();
        JDBC = new JdbcTemplate(ValidationDbFixture.bootstrap(PG));
        ADMIN = new JdbcTemplate(new DriverManagerDataSource(PG.getJdbcUrl(), PG.getUsername(), PG.getPassword()));
    }

    /** R13 e: definition_version = 원 지표 뷰들의 값 (V4 = ADR-S4-01 v1.4, V6 = v1.7) */
    private static final String DEF = MetricFixture.DEF_VERSION;

    private static int take(UUID run) {
        return JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
    }

    private static List<Map<String, Object>> snapshot(UUID run, String definitionVersion) {
        return JDBC.queryForList("SELECT * FROM validation.metric_snapshot WHERE run_id = ? AND definition_version = ? "
                + "ORDER BY metric_id, scope_kind, scope_key", run, definitionVersion);
    }

    private static Map<String, Map<String, Object>> byKey(List<Map<String, Object>> rows) {
        return rows.stream().collect(Collectors.toMap(
                r -> r.get("metric_id") + "|" + r.get("scope_kind") + "|" + r.get("scope_key"), Function.identity()));
    }

    private static Map<String, Object> row(Map<String, Map<String, Object>> rows, String metric, String kind, String key) {
        Map<String, Object> r = rows.get(metric + "|" + kind + "|" + key);
        assertNotNull(r, metric + " " + kind + ":" + key);
        return r;
    }

    private static String xn(Map<String, Object> r) {
        return l(r, "numerator") + "/" + l(r, "denominator");
    }

    private static String message(Throwable e) {
        Throwable t = e;
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            sb.append(t.getMessage()).append(" | ");
            t = t.getCause();
        }
        return sb.toString();
    }

    // ---- T1 ----

    /** 열 순서: ALL / SQLI / PT / BF / SSRF / UNKNOWN // T1190 / T1110 — MetricRatesViewTest 손계산 그대로 */
    private static final Map<String, List<String>> F1_RATES = Map.of(
            "M01", List.of("7/10", "4/5", "1/3", "1/1", "0/0", "1/1", "6/9", "1/1"),
            "M02", List.of("5/7", "3/4", "1/1", "0/1", "0/0", "1/1", "5/6", "0/1"),
            "M03", List.of("2/7", "1/4", "0/1", "1/1", "0/0", "0/1", "1/6", "1/1"),
            "M02_INITIAL", List.of("4/7", "3/4", "0/1", "0/1", "0/0", "1/1", "4/6", "0/1"),
            "M03_INITIAL", List.of("3/7", "1/4", "1/1", "1/1", "0/0", "0/1", "2/6", "1/1"),
            "M08", List.of("1/11", "1/6", "0/3", "0/1", "0/0", "0/1", "1/10", "0/1"));
    private static final List<String[]> SPLITS = List.of(
            new String[] {"ALL", "ALL"}, new String[] {"SCENARIO", "SQLI"}, new String[] {"SCENARIO", "PATH_TRAVERSAL"},
            new String[] {"SCENARIO", "BRUTE_FORCE"}, new String[] {"SCENARIO", "SSRF"}, new String[] {"SCENARIO", "UNKNOWN"},
            new String[] {"TECHNIQUE", "T1190"}, new String[] {"TECHNIQUE", "T1110"});

    /** 뷰별 행 수 — 스냅샷은 뷰 행을 그대로 옮기고 H2 1행만 관측 2개(RID+HEADER·NONE)로 나눈다 */
    private static Map<String, Long> viewRowCounts(UUID run) {
        Map<String, Long> counts = new HashMap<>();
        for (String view : List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation", "v_metric_h2",
                "v_metric_coverage", "v_metric_attacker", "v_metric_m07a", "v_metric_m13")) {
            counts.put(view, JDBC.queryForObject("SELECT count(*) FROM validation." + view + " WHERE run_id = ?",
                    Long.class, run));
        }
        return counts;
    }

    @Test
    void t1F1SnapshotCopiesEveryViewRowWithHandComputedValues() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        Map<String, Long> views = viewRowCounts(run);

        int inserted = take(run);

        List<Map<String, Object>> rows = snapshot(run, DEF);
        assertEquals(rows.size(), inserted);
        Map<String, Long> bySource = rows.stream().collect(Collectors.groupingBy(
                r -> (String) r.get("source_view"), Collectors.counting()));
        for (Map.Entry<String, Long> v : views.entrySet()) {
            long expected = "v_metric_h2".equals(v.getKey()) ? 2 * v.getValue() : v.getValue();
            assertEquals(expected, bySource.getOrDefault(v.getKey(), 0L), v.getKey());
        }
        assertEquals(views.values().stream().mapToLong(Long::longValue).sum() + views.get("v_metric_h2"), inserted);

        Map<String, Map<String, Object>> s = byKey(rows);
        // 비율 지표 (MetricRatesViewTest 손계산)
        F1_RATES.forEach((metric, expected) -> {
            for (int i = 0; i < SPLITS.size(); i++) {
                assertEquals(expected.get(i), xn(row(s, metric, SPLITS.get(i)[0], SPLITS.get(i)[1])), metric + " " + i);
            }
        });
        assertEquals("1/1", xn(row(s, "M07b", "SCENARIO", "SQLI")));
        assertEquals("1/2", xn(row(s, "M07b", "SCENARIO", "PATH_TRAVERSAL")));
        assertEquals("0/0", xn(row(s, "M07b", "SCENARIO", "BRUTE_FORCE")));
        assertEquals("1/6", xn(row(s, "M10", "ALL", "ALL")));
        assertEquals("1/2", xn(row(s, "M10", "SCENARIO", "PATH_TRAVERSAL")));
        // M12 = NOT_APPLICABLE 그대로, 수치 전부 NULL (R8)
        Map<String, Object> m12 = row(s, "M12", "ALL", "ALL");
        assertEquals("NOT_APPLICABLE", m12.get("status"));
        for (String k : List.of("numerator", "denominator", "point_estimate", "ci_lower", "ci_upper")) {
            assertNull(m12.get(k), "M12 " + k);
        }
        // M04 MTTD (MttdViewTest)
        assertMttd(row(s, "M04", "ALL", "ALL"), 4, 2500, 5000);
        assertMttd(row(s, "M04", "SCENARIO", "SQLI"), 3, 2000, 3000);
        assertMttd(row(s, "M04", "SCENARIO", "UNKNOWN"), 1, 5000, 5000);
        assertMttd(row(s, "M04", "TECHNIQUE", "T1190"), 4, 2500, 5000);
        Map<String, Object> ptMttd = row(s, "M04", "SCENARIO", "PATH_TRAVERSAL");
        assertEquals(0L, l(ptMttd, "denominator"));
        assertNull(ptMttd.get("p50_ms"));
        assertEquals("NO_DATA", ptMttd.get("status"));
        // M06a·M06b (CoverageViewTest)
        assertEquals("1/2", xn(row(s, "M06a", "TECHNIQUE", "ALL")));
        assertEquals("0/2", xn(row(s, "M06b", "TECHNIQUE", "ALL")));
        assertEquals("2/4", xn(row(s, "M06a", "SCENARIO", "ALL")));
        assertEquals("1/4", xn(row(s, "M06b", "SCENARIO", "ALL")));
        // M09 (AttackerAccuracyViewTest: SQLI n5 x4 과대평가 1 → n<20 이라 기준 미충족)
        Map<String, Object> m09 = row(s, "M09", "SCENARIO", "SQLI");
        assertEquals("4/5", xn(m09));
        assertEquals(1L, l(m09, "overestimate_count"));
        assertEquals("OK", m09.get("status"));
        assertEquals(false, m09.get("criteria_met"));
        // M05: F1 은 링크 없음 → 분포 n=0, H2 n=0 (InvariantTest) → INCONCLUSIVE
        Map<String, Object> h2 = row(s, "M05_H2_RID_HEADER", "ALL", "ALL");
        assertEquals(0L, l(h2, "denominator"));
        assertEquals("INCONCLUSIVE", h2.get("status"));
        assertEquals("INCONCLUSIVE", row(s, "M05_H2_NONE", "ALL", "ALL").get("status"));

        assertEqualsLiveViews(run, s);
    }

    private static void assertMttd(Map<String, Object> r, long n, double p50, double p95) {
        assertEquals(n, l(r, "denominator"));
        assertNull(r.get("numerator"));
        assertEquals(p50, d(r, "p50_ms"), 1e-9);
        assertEquals(p95, d(r, "p95_ms"), 1e-9);
        assertEquals("OK", r.get("status"));
    }

    /** 나머지 값(점추정·구간·백분위·판정) = 같은 run 의 라이브 뷰 값 — 복사 충실도 */
    private static void assertEqualsLiveViews(UUID run, Map<String, Map<String, Object>> s) {
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_rates WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, (String) v.get("metric_id"), (String) v.get("split_kind"), (String) v.get("split_unit"));
            assertCopied(v, "x", r, "numerator");
            assertCopied(v, "n", r, "denominator");
            assertCopied(v, "p", r, "point_estimate");
            assertCopied(v, "lo", r, "ci_lower");
            assertCopied(v, "hi", r, "ci_upper");
            assertEquals(v.get("status"), r.get("status"));
        }
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_mttd WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, "M04", (String) v.get("split_kind"), (String) v.get("split_unit"));
            assertCopied(v, "n", r, "denominator");
            assertCopied(v, "p50_ms", r, "p50_ms");
            assertCopied(v, "p95_ms", r, "p95_ms");
        }
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_correlation WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, "M05_" + v.get("source"), (String) v.get("split_kind"), (String) v.get("split_unit"));
            assertCopied(v, "x", r, "numerator");
            assertCopied(v, "n", r, "denominator");
            assertCopied(v, "lo", r, "ci_lower");
            assertCopied(v, "hi", r, "ci_upper");
        }
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_h2 WHERE run_id = ?", run)) {
            Map<String, Object> rh = row(s, "M05_H2_RID_HEADER", "ALL", "ALL");
            Map<String, Object> nn = row(s, "M05_H2_NONE", "ALL", "ALL");
            assertCopied(v, "rid_header_x", rh, "numerator");
            assertCopied(v, "rid_header_lo", rh, "ci_lower");
            assertCopied(v, "none_x", nn, "numerator");
            assertCopied(v, "none_hi", nn, "ci_upper");
            assertEquals(v.get("h2_status"), rh.get("status"));
            assertEquals(v.get("h2_status"), nn.get("status"));
        }
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_coverage WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, (String) v.get("metric_id"), (String) v.get("split_kind"), "ALL");
            assertCopied(v, "x", r, "numerator");
            assertCopied(v, "lo", r, "ci_lower");
        }
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_attacker WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, "M09", (String) v.get("split_kind"), (String) v.get("split_unit"));
            assertCopied(v, "x", r, "numerator");
            assertCopied(v, "n", r, "denominator");
            assertCopied(v, "lo", r, "ci_lower");
            assertCopied(v, "overestimate", r, "overestimate_count");
            assertCopied(v, "uncertain", r, "uncertain_count");
            assertEquals(v.get("criteria_met"), r.get("criteria_met"));
            assertEquals(v.get("status"), r.get("status"));
        }
    }

    private static void assertCopied(Map<String, Object> view, String viewKey, Map<String, Object> snap, String snapKey) {
        Object a = view.get(viewKey);
        Object b = snap.get(snapKey);
        if (a == null || b == null) {
            assertEquals(a, b, viewKey + "→" + snapKey + " " + snap);
        } else {
            assertEquals(((Number) a).doubleValue(), ((Number) b).doubleValue(), 0.0, viewKey + "→" + snapKey + " " + snap);
        }
    }

    /** M05 0 아닌 값 — CorrelationViewTest 픽스처 A 와 기대값 그대로 */
    @Test
    void t1CorrelationFixtureACopiesSourceDistributionAndH2() {
        UUID run = new MetricFixture(JDBC)
                .add(4, a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links(null, "NONE", "RID"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("HEADER"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("UA_FALLBACK"))
                .add(a("SQLI", "T1190", "UNCERTAIN").links("NONE"))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED").links((String) null))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID").control())
                .close(MetricFixture.Close.VALID);

        take(run);

        Map<String, Map<String, Object>> s = byKey(snapshot(run, DEF));
        assertEquals("5/8", xn(row(s, "M05_RID", "ALL", "ALL")));
        assertEquals("1/8", xn(row(s, "M05_HEADER", "ALL", "ALL")));
        assertEquals("1/8", xn(row(s, "M05_UA_FALLBACK", "ALL", "ALL")));
        assertEquals("1/8", xn(row(s, "M05_NONE", "ALL", "ALL")));
        assertEquals("5/8", xn(row(s, "M05_RID", "SCENARIO", "SQLI")));
        assertEquals("6/8", xn(row(s, "M05_H2_RID_HEADER", "ALL", "ALL")));
        assertEquals("1/8", xn(row(s, "M05_H2_NONE", "ALL", "ALL")));
        assertEquals("INCONCLUSIVE", row(s, "M05_H2_RID_HEADER", "ALL", "ALL").get("status"));
        assertEqualsLiveViews(run, s);
    }

    /** R13 f 예: 전부 성공 20/20 → Wilson 하한 0.838875 (crosscheck 증거 값) */
    @Test
    void t1AllSuccessLowerBoundMatchesCrosscheckEvidence() {
        UUID run = new MetricFixture(JDBC)
                .add(20, a("SQLI", "T1190", "SUCCEEDED_DETECTED").mttd(1000))
                .close(MetricFixture.Close.VALID);

        take(run);

        Map<String, Object> m02 = row(byKey(snapshot(run, DEF)), "M02", "SCENARIO", "SQLI");
        assertEquals("20/20", xn(m02));
        assertEquals(1.0, d(m02, "point_estimate"), 0.0);
        assertEquals(0.838875, d(m02, "ci_lower"), 1e-6);
        assertEquals(1.0, d(m02, "ci_upper"), 0.0);
    }

    // ---- T2 ----

    @Test
    void t2InvalidAndIncompleteRunsAreRefusedWithR10Status() {
        UUID invalid = new MetricFixture(JDBC).add(a("SQLI", "T1190", "SUCCEEDED_DETECTED")).close(MetricFixture.Close.INVALID);
        UUID incomplete = new MetricFixture(JDBC).add(a("SQLI", "T1190", "SUCCEEDED_DETECTED")).close(MetricFixture.Close.OPEN);

        DataAccessException e1 = assertThrows(DataAccessException.class, () -> take(invalid));
        assertTrue(message(e1).contains("INVALID"), message(e1));
        assertTrue(message(e1).contains("ATTACK_MISMATCH"), message(e1));
        DataAccessException e2 = assertThrows(DataAccessException.class, () -> take(incomplete));
        assertTrue(message(e2).contains("INCOMPLETE"), message(e2));

        assertEquals(0, snapshot(invalid, DEF).size());
        assertEquals(0, snapshot(incomplete, DEF).size());
    }

    // ---- T3 ----

    @Test
    void t3UpdateDeleteTruncateAreRefusedByPrivilegeAndByTrigger() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        take(run);
        List<Map<String, Object>> before = snapshot(run, DEF);

        // validation_rw (소유자, 일반 DML): REVOKE 로 권한 거부
        for (String sql : List.of(
                "UPDATE validation.metric_snapshot SET numerator = 0 WHERE run_id = '" + run + "'",
                "DELETE FROM validation.metric_snapshot WHERE run_id = '" + run + "'",
                "TRUNCATE validation.metric_snapshot")) {
            DataAccessException e = assertThrows(DataAccessException.class, () -> JDBC.execute(sql), sql);
            assertTrue(message(e).contains("permission denied"), sql + " → " + message(e));
        }
        // superuser (권한 검사 우회): 트리거가 거부
        for (String sql : List.of(
                "UPDATE validation.metric_snapshot SET numerator = 0 WHERE run_id = '" + run + "'",
                "DELETE FROM validation.metric_snapshot WHERE run_id = '" + run + "'",
                "TRUNCATE validation.metric_snapshot")) {
            DataAccessException e = assertThrows(DataAccessException.class, () -> ADMIN.execute(sql), sql);
            assertTrue(message(e).contains("metric_snapshot 는 불변"), sql + " → " + message(e));
        }

        assertEquals(before, snapshot(run, DEF));
    }

    // ---- T4 ----

    @Test
    void t4SameRunAndDefinitionVersionTwiceIsRefused() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        int first = take(run);

        DataAccessException e = assertThrows(DataAccessException.class, () -> take(run));
        assertTrue(message(e).contains("이미"), message(e));
        assertEquals(first, snapshot(run, DEF).size());
        // 정의가 바뀌었을 때 새 definition_version 행으로 추가되는 것은 MetricSnapshotDefinitionVersionTest
    }

    // ---- T5 ----

    @Test
    void t5EmptyScopeKeepsZeroCountsAndNullEstimates() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        take(run);

        List<Map<String, Object>> empty = snapshot(run, DEF).stream()
                .filter(r -> r.get("denominator") != null && l(r, "denominator") == 0)
                .toList();
        assertTrue(empty.size() > 0);
        for (Map<String, Object> r : empty) {
            if (r.get("numerator") != null) {
                assertEquals(0L, l(r, "numerator"), r.toString());
            }
            for (String k : List.of("point_estimate", "ci_lower", "ci_upper", "p50_ms", "p95_ms")) {
                assertNull(r.get(k), k + " " + r);
            }
        }
        Map<String, Object> ssrf = row(byKey(snapshot(run, DEF)), "M02", "SCENARIO", "SSRF");
        assertEquals("0/0", xn(ssrf));
        assertEquals("NO_DATA", ssrf.get("status"));
    }

    // ---- T6 ----

    @Test
    void t6InvariantsHoldInsideTheSnapshot() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        take(run);
        List<Map<String, Object>> rows = snapshot(run, DEF);
        Map<String, Map<String, Object>> s = byKey(rows);

        // I1: M02 + M03 = 1 (S_ALL > 0)
        int checked = 0;
        for (Map<String, Object> m02 : rows) {
            if (!"M02".equals(m02.get("metric_id")) || l(m02, "denominator") == 0) {
                continue;
            }
            Map<String, Object> m03 = row(s, "M03", (String) m02.get("scope_kind"), (String) m02.get("scope_key"));
            assertEquals(l(m02, "denominator"), l(m03, "denominator"));
            assertEquals(l(m02, "denominator"), l(m02, "numerator") + l(m03, "numerator"));
            assertEquals(1.0, d(m02, "point_estimate") + d(m03, "point_estimate"), 1e-12);
            checked++;
        }
        assertTrue(checked > 0);
        // I4: 0 ≤ 하한 ≤ 점추정 ≤ 상한 ≤ 1
        for (Map<String, Object> r : rows) {
            if (r.get("point_estimate") == null) {
                continue;
            }
            double lo = d(r, "ci_lower");
            double p = d(r, "point_estimate");
            double hi = d(r, "ci_upper");
            assertTrue(0 <= lo && lo <= p && p <= hi && hi <= 1, r.toString());
        }
        // I6: Σ 시나리오 n(UNKNOWN 포함) = ALL n = Σ 기법 n (검증 기준 M08)
        long all = l(row(s, "M08", "ALL", "ALL"), "denominator");
        long scenarios = rows.stream().filter(r -> "M08".equals(r.get("metric_id")) && "SCENARIO".equals(r.get("scope_kind")))
                .mapToLong(r -> l(r, "denominator")).sum();
        long techniques = rows.stream().filter(r -> "M08".equals(r.get("metric_id")) && "TECHNIQUE".equals(r.get("scope_kind")))
                .mapToLong(r -> l(r, "denominator")).sum();
        assertEquals(11L, all);
        assertEquals(all, scenarios);
        assertEquals(all, techniques);
    }

    // ---- T7 ----

    @Test
    void t7ProvenanceColumnsAreCopiedFromTheRun() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        JDBC.update("UPDATE validation.measurement_run SET git_commit = 'abc123', git_dirty = true, "
                + "rules_digest = '{\"wazuh_rules\": \"w1\"}'::jsonb WHERE run_id = ?", run);
        take(run);

        String latest = JDBC.queryForObject("SELECT version FROM validation.flyway_schema_history WHERE success "
                + "AND version IS NOT NULL ORDER BY installed_rank DESC LIMIT 1", String.class);
        assertEquals("13", latest); // V13 benign final correlation 추가
        for (Map<String, Object> r : JDBC.queryForList("""
                SELECT definition_version, snapshot_rule_version, schema_version, run_label, git_commit, git_dirty,
                       rules_digest::text AS rules_digest, snapshot_at, source_view
                FROM validation.metric_snapshot WHERE run_id = ? AND definition_version = ?""", run, DEF)) {
            assertEquals(DEF, r.get("definition_version"));
            assertEquals("ADR-S4-01 v1.6", r.get("snapshot_rule_version"));
            assertEquals(latest, r.get("schema_version"));
            assertEquals("test-" + run, r.get("run_label"));
            assertEquals("abc123", r.get("git_commit"));
            assertEquals(true, r.get("git_dirty"));
            assertEquals("{\"wazuh_rules\": \"w1\"}", r.get("rules_digest"));
            assertNotNull(r.get("snapshot_at"));
            assertNotNull(r.get("source_view"));
        }
        // 컬럼 NULL 허용: 출처는 NOT NULL, git_dirty 만 run 값(백필 run NULL) 그대로 허용
        Map<String, String> nullable = JDBC.queryForList("""
                SELECT column_name, is_nullable FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'metric_snapshot'""").stream()
                .collect(Collectors.toMap(c -> (String) c.get("column_name"), c -> (String) c.get("is_nullable")));
        for (String c : List.of("run_id", "definition_version", "metric_id", "scope_kind", "scope_key", "status",
                "source_view", "snapshot_rule_version", "schema_version", "run_label", "git_commit", "rules_digest",
                "snapshot_at")) {
            assertEquals("NO", nullable.get(c), c);
        }
        assertEquals("YES", nullable.get("git_dirty"));
    }

    // ---- T10 ----

    /** R13 c: status·criteria_met 은 원 뷰 값 그대로 — 변환 없음 (M12 NOT_APPLICABLE, H2 h2_status, M09 criteria_met boolean) */
    @Test
    void t10StatusAndCriteriaMetAreCopiedVerbatim() {
        UUID run = new MetricFixture(JDBC)
                .add(20, a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_MISSED"))
                .close(MetricFixture.Close.VALID);
        take(run);
        Map<String, Map<String, Object>> s = byKey(snapshot(run, DEF));

        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_rates WHERE run_id = ?", run)) {
            assertEquals(v.get("status"), row(s, (String) v.get("metric_id"), (String) v.get("split_kind"),
                    (String) v.get("split_unit")).get("status"));
            seen.add((String) v.get("status"));
        }
        assertTrue(seen.contains("NOT_APPLICABLE") && seen.contains("NO_DATA") && seen.contains("OK"), seen.toString());
        Map<String, Object> h2 = JDBC.queryForMap("SELECT h2_status FROM validation.v_metric_h2 WHERE run_id = ?", run);
        assertEquals(h2.get("h2_status"), row(s, "M05_H2_RID_HEADER", "ALL", "ALL").get("status"));
        assertEquals(h2.get("h2_status"), row(s, "M05_H2_NONE", "ALL", "ALL").get("status"));
        int criteria = 0;
        for (Map<String, Object> v : JDBC.queryForList("SELECT * FROM validation.v_metric_attacker WHERE run_id = ?", run)) {
            Map<String, Object> r = row(s, "M09", "SCENARIO", (String) v.get("split_unit"));
            assertEquals(v.get("status"), r.get("status"));
            assertTrue(r.get("criteria_met") instanceof Boolean, r.toString());
            assertEquals(v.get("criteria_met"), r.get("criteria_met"));
            if (Boolean.TRUE.equals(r.get("criteria_met"))) {
                criteria++;
            }
        }
        assertEquals(1, criteria, "SQLI 20/20 만 criteria_met"); // AttackerAccuracyViewTest 기준(n ≥ 20 ∧ ≥ 0.95 ∧ 과대평가 0)
        for (Map<String, Object> r : s.values()) {
            if (!"M09".equals(r.get("metric_id"))) {
                assertNull(r.get("criteria_met"), r.toString());
            }
        }
    }

    // ---- T11 ----

    /**
     * B1: run_id 컬럼 UPDATE 만 허용(measurement_run 삭제 때 FK 확인 쿼리의 FOR KEY SHARE 용) — 실제 수정은 트리거가 막고
     * 다른 컬럼은 권한 거부. run 삭제는 스냅샷 유무로 갈린다(스냅샷 있음 = FK ON DELETE RESTRICT, 없음 = 삭제 가능).
     */
    @Test
    void t11RunIdColumnGrantOnlyServesForeignKeyChecks() {
        // verdict 0건 VALID run(기대 0/0) — measurement_run 을 참조하는 것이 스냅샷·철회 행뿐이게
        UUID withSnapshot = new MetricFixture(JDBC).close(MetricFixture.Close.VALID);
        assertTrue(take(withSnapshot) > 0);
        JDBC.queryForObject("SELECT validation.withdraw_metric_snapshot(?, ?, ?)", Long.class, withSnapshot, DEF, "T11 철회 행");

        for (String table : List.of("metric_snapshot", "metric_snapshot_withdrawal")) {
            String runIdUpdate = "UPDATE validation." + table + " SET run_id = run_id WHERE run_id = '" + withSnapshot + "'";
            DataAccessException byTrigger = assertThrows(DataAccessException.class, () -> JDBC.execute(runIdUpdate), runIdUpdate);
            assertTrue(message(byTrigger).contains(table + " 는 불변"), runIdUpdate + " → " + message(byTrigger));
        }
        for (String otherColumn : List.of(
                "UPDATE validation.metric_snapshot SET status = 'X' WHERE run_id = '" + withSnapshot + "'",
                "UPDATE validation.metric_snapshot_withdrawal SET reason = 'X' WHERE run_id = '" + withSnapshot + "'")) {
            DataAccessException byRole = assertThrows(DataAccessException.class, () -> JDBC.execute(otherColumn), otherColumn);
            assertTrue(message(byRole).contains("permission denied"), otherColumn + " → " + message(byRole));
        }

        DataAccessException fk = assertThrows(DataAccessException.class,
                () -> JDBC.update("DELETE FROM validation.measurement_run WHERE run_id = ?", withSnapshot));
        assertTrue(message(fk).contains("violates foreign key constraint") && message(fk).contains("metric_snapshot"),
                message(fk));
        assertEquals(1, JDBC.queryForObject("SELECT count(*) FROM validation.measurement_run WHERE run_id = ?",
                Integer.class, withSnapshot));

        UUID withoutSnapshot = TestRuns.openTestRun(JDBC);
        assertEquals(1, JDBC.update("DELETE FROM validation.measurement_run WHERE run_id = ?", withoutSnapshot));
    }

    // ---- T8 ----

    @Test
    void t8WithdrawalKeepsTheSnapshotAndIsItselfAppendOnly() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        take(run);
        List<Map<String, Object>> before = snapshot(run, DEF);

        Long id = JDBC.queryForObject("SELECT validation.withdraw_metric_snapshot(?, ?, ?)", Long.class,
                run, DEF, "테스트 철회 — 픽스처 정의 오류 가정");
        assertNotNull(id);
        assertEquals(before, snapshot(run, DEF), "철회해도 원 스냅샷 행은 그대로");
        assertEquals(1, JDBC.queryForObject("SELECT count(*) FROM validation.metric_snapshot_withdrawal "
                + "WHERE run_id = ? AND definition_version = ?", Integer.class, run, DEF));

        for (String sql : List.of(
                "UPDATE validation.metric_snapshot_withdrawal SET reason = 'x' WHERE run_id = '" + run + "'",
                "DELETE FROM validation.metric_snapshot_withdrawal WHERE run_id = '" + run + "'",
                "TRUNCATE validation.metric_snapshot_withdrawal")) {
            DataAccessException byRole = assertThrows(DataAccessException.class, () -> JDBC.execute(sql), sql);
            assertTrue(message(byRole).contains("permission denied"), sql + " → " + message(byRole));
            DataAccessException byTrigger = assertThrows(DataAccessException.class, () -> ADMIN.execute(sql), sql);
            assertTrue(message(byTrigger).contains("metric_snapshot_withdrawal 는 불변"), sql + " → " + message(byTrigger));
        }

        DataAccessException again = assertThrows(DataAccessException.class, () -> JDBC.queryForObject(
                "SELECT validation.withdraw_metric_snapshot(?, ?, ?)", Long.class, run, DEF, "두 번째"));
        assertTrue(message(again).contains("이미"), message(again));
        DataAccessException missing = assertThrows(DataAccessException.class, () -> JDBC.queryForObject(
                "SELECT validation.withdraw_metric_snapshot(?, ?, ?)", Long.class, run, "9.9-none", "없는 스냅샷"));
        assertTrue(message(missing).contains("스냅샷 없음"), message(missing));
        DataAccessException blank = assertThrows(DataAccessException.class, () -> JDBC.queryForObject(
                "SELECT validation.withdraw_metric_snapshot(?, ?, ?)", Long.class, run, DEF, " "));
        assertTrue(message(blank).contains("사유"), message(blank));
    }
}
