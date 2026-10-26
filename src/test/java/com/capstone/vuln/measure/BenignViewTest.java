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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * V7 — R10 BENIGN 분기(R17 d), v_metric_m14a(R18 a·b·d·f), M14b 짝 없음(R18 e). 기대값은 픽스처 손계산.
 * 짝 run 이 있는 M14b 와 스냅샷은 불변 행을 남기므로 BenignSnapshotTest(전용 컨테이너).
 */
class BenignViewTest extends ValidationDbFixture {

    @BeforeEach
    void clean() {
        JDBC.execute("TRUNCATE validation.benign_result, validation.benign_request, validation.benign_unlinked_alert");
        truncateRunData();
    }

    private static Map<String, Object> integrity(UUID run) {
        return JDBC.queryForMap("SELECT * FROM validation.v_run_integrity WHERE run_id = ?", run);
    }

    // ---- R10 BENIGN ----

    @Test
    void r10BenignValidWhenExpectedEqualsLoadedEqualsMatched() {
        BenignFixture f = new BenignFixture(JDBC).requests("/api/products/search", 5, 5, 0, 0);
        Map<String, Object> r = integrity(f.close(5, true));
        assertEquals("VALID", r.get("r10_status"));
        assertNull(r.get("r10_reason"));
        assertEquals(5L, l(r, "benign_loaded"));
        assertEquals(5L, l(r, "benign_matched"));
    }

    @Test
    void r10BenignInvalidReasonsAndIncomplete() {
        Map<String, Object> load = integrity(new BenignFixture(JDBC).requests("/api/products/search", 5, 5, 0, 0)
                .close(6, true));
        assertEquals("INVALID", load.get("r10_status"));
        assertEquals("BENIGN_LOAD_MISMATCH", load.get("r10_reason"));

        Map<String, Object> match = integrity(new BenignFixture(JDBC).requests("/api/products/search", 5, 4, 0, 0)
                .close(5, true));
        assertEquals("INVALID", match.get("r10_status"));
        assertEquals("BENIGN_MATCH_MISMATCH", match.get("r10_reason"));

        Map<String, Object> missing = integrity(new BenignFixture(JDBC).requests("/api/products/search", 2, 2, 0, 0)
                .close(null, true));
        assertEquals("EXPECTED_MISSING", missing.get("r10_reason"));

        Map<String, Object> open = integrity(new BenignFixture(JDBC).requests("/api/products/search", 2, 2, 0, 0)
                .close(2, false));
        assertEquals("INCOMPLETE", open.get("r10_status"));
    }

    /** benign_request 가 0행인 BENIGN run 은 ATTACK verdict 수와 무관하게 INVALID(BENIGN_LOAD_MISMATCH) */
    @Test
    void r10BenignWithoutRequestsIsLoadMismatchEvenWithAttackVerdicts() {
        UUID run = new BenignFixture(JDBC).close(3, false);
        com.capstone.vuln.correlation.TestRuns.insertVerdict(JDBC, run, "unit:benign-attack-1", "ATTACK");
        com.capstone.vuln.correlation.TestRuns.insertVerdict(JDBC, run, "unit:benign-attack-2", "ATTACK");
        com.capstone.vuln.correlation.TestRuns.insertVerdict(JDBC, run, "unit:benign-attack-3", "ATTACK");
        JDBC.update("UPDATE validation.measurement_run SET status = 'CLOSED', ended_at = now() WHERE run_id = ?", run);

        Map<String, Object> r = integrity(run);
        assertEquals("INVALID", r.get("r10_status"));
        assertEquals("BENIGN_LOAD_MISMATCH", r.get("r10_reason"));
        assertEquals(0L, l(r, "benign_loaded"));
        assertEquals(3L, l(r, "actual_attack"), "ATTACK 수가 기대 수와 같아도 BENIGN 은 정상 요청 적재 수로만 판정");
    }

    /** INVALID run 은 M14 뷰에 없다 */
    @Test
    void invalidBenignRunHasNoM14Rows() {
        UUID run = new BenignFixture(JDBC).requests("/api/products/search", 5, 4, 0, 0).close(5, true);
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m14a WHERE run_id = ?",
                Integer.class, run));
    }

    // ---- M14a ----

    private static Map<String, Object> m14a(UUID run, String control, String endpoint) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_m14a WHERE run_id = ? AND metric_id = ? AND endpoint = ?",
                run, "M14a_" + control, endpoint);
    }

    /**
     * search 300 (FP 0/0), download 300 (APP_RULE FP 3, NIDS 0), preview 300 (APP_RULE 0, NIDS 6).
     * 0/300 상한 = z²/(n+z²) = 3.841459/303.841459 = 0.012643 (z = 1.959964). 웹 run 이라 login 행 없음.
     */
    @Test
    void m14aPerControlAndEndpoint() {
        UUID run = new BenignFixture(JDBC)
                .requests("/api/products/search", 300, 300, 0, 0)
                .requests("/api/files/download", 300, 300, 3, 0)
                .requests("/api/preview", 300, 300, 0, 6)
                .close(900, true);

        Map<String, Object> s = m14a(run, "APP_RULE", "/api/products/search");
        assertEquals(0L, l(s, "x"));
        assertEquals(300L, l(s, "n"));
        assertEquals(0.0, d(s, "p"), 0.0);
        assertEquals(0.012643, d(s, "hi"), 1e-6);
        assertEquals("OK", s.get("status"));
        assertEquals("SQLI", s.get("split_unit"));
        assertEquals("SCENARIO", s.get("split_kind"));
        assertEquals("ADR-S4-01 v2.0", s.get("definition_version"));

        assertEquals(3L, l(m14a(run, "APP_RULE", "/api/files/download"), "x"));
        assertEquals("PATH_TRAVERSAL", m14a(run, "APP_RULE", "/api/files/download").get("split_unit"));
        assertEquals(6L, l(m14a(run, "NIDS", "/api/preview"), "x"));
        assertEquals(0L, l(m14a(run, "NIDS", "/api/files/download"), "x"));
        Map<String, Object> ci = JDBC.queryForMap("SELECT p, lo, hi FROM validation.wilson_ci(6, 300)");
        assertEquals(d(ci, "hi"), d(m14a(run, "NIDS", "/api/preview"), "hi"), 1e-12);

        Map<String, Object> backend = m14a(run, "BACKEND_CORR", "/api/preview");
        assertEquals("NO_RULE", backend.get("status"));
        assertNull(backend.get("x"));
        assertNull(backend.get("p"));
        assertEquals(300L, l(backend, "n"));

        // 엔드포인트 3 × 통제 3, login 은 run 없음 → 행 없음
        assertEquals(9, JDBC.queryForObject("SELECT count(*) FROM validation.v_metric_m14a WHERE run_id = ?",
                Integer.class, run));
    }

    /** 적용 통제의 결과 행이 요청 수와 다르면 값 대신 RESULT_MISMATCH (조용한 과소 집계 방지) */
    @Test
    void m14aMissingResultRowsAreFlagged() {
        BenignFixture f = new BenignFixture(JDBC).requests("/api/products/search", 3, 3, 0, 0);
        JDBC.update("DELETE FROM validation.benign_result WHERE run_id = ? AND seq = 1 AND control = 'NIDS'", f.runId);
        UUID run = f.close(3, true);
        Map<String, Object> r = m14a(run, "NIDS", "/api/products/search");
        assertEquals("RESULT_MISMATCH", r.get("status"));
        assertNull(r.get("x"));
        assertEquals("OK", m14a(run, "APP_RULE", "/api/products/search").get("status"));
    }

    // ---- M14b 짝 없음 ----

    @Test
    void m14bWithoutPairIsNoPair() {
        UUID run = new BenignFixture(JDBC, "{\"wazuh_rules\":\"nothing-matches\"}")
                .requests("/api/files/download", 2, 2, 1, 0).close(2, true);
        List<Map<String, Object>> rows = JDBC.queryForList(
                "SELECT * FROM validation.v_metric_m14b WHERE run_id = ? ORDER BY metric_id", run);
        assertEquals(3, rows.size());
        Map<String, Object> app = rows.stream().filter(r -> "M14b_APP_RULE".equals(r.get("metric_id"))).findFirst().orElseThrow();
        assertEquals("NO_PAIR", app.get("status"));
        assertNull(app.get("paired_run_id"));
        assertNull(app.get("x"));
        Map<String, Object> backend = rows.stream().filter(r -> "M14b_BACKEND_CORR".equals(r.get("metric_id")))
                .findFirst().orElseThrow();
        assertEquals("NO_RULE", backend.get("status"), "BACKEND_CORR × 웹 = NO_RULE (R18 b)");
        assertNull(backend.get("n"));
    }

    /**
     * v1.9: 통제의 M14a 칸이 모두 비적용이면 M14b 상태 = 그 칸의 상태 — M13·M14a·M14b 같은 규칙.
     * 웹 run 의 BACKEND_CORR: M14a 3칸 NO_RULE → M14b NO_RULE (짝 유무와 무관), M13 BACKEND_CORR × 웹 시나리오도 NO_RULE.
     */
    @Test
    void inapplicableControlStatusIsTheSameAcrossM13M14aM14b() {
        UUID web = new BenignFixture(JDBC).requests("/api/products/search", 2, 2, 0, 0)
                .requests("/api/preview", 2, 2, 0, 0).close(4, true);
        UUID attack = new MetricFixture(JDBC).add(a("SQLI", "T1190", "SUCCEEDED_DETECTED"))
                .close(MetricFixture.Close.VALID);

        assertEquals(List.of("NO_RULE"), JDBC.queryForList("SELECT DISTINCT status FROM validation.v_metric_m14a "
                + "WHERE run_id = ? AND control = 'BACKEND_CORR'", String.class, web));
        assertEquals("NO_RULE", JDBC.queryForObject("SELECT status FROM validation.v_metric_m14b "
                + "WHERE run_id = ? AND control = 'BACKEND_CORR'", String.class, web));
        assertEquals("NO_RULE", JDBC.queryForObject("SELECT status FROM validation.v_metric_m13 "
                + "WHERE run_id = ? AND control = 'BACKEND_CORR' AND split_unit = 'SQLI'", String.class, attack));
        // 적용 통제는 그대로 짝 판정(짝 없음)
        assertEquals("NO_PAIR", JDBC.queryForObject("SELECT status FROM validation.v_metric_m14b "
                + "WHERE run_id = ? AND control = 'APP_RULE'", String.class, web));
    }

    // ---- 적재 ----

    /** BenignRunRepository: 요청 2건(1건 대조 실패), 결과 2행, 미연결 1행 → 값 원문 대신 args_digest, R10 = MATCH_MISMATCH */
    @Test
    void repositoryStoresRequestsResultsAndUnlinkedWithDigestOnly() {
        UUID run = new BenignFixture(JDBC).close(2, false);
        java.time.Instant t = BenignFixture.T0;
        List<BenignSent> sent = List.of(
                new BenignSent(1, "/api/products/search", "/api/products/search?keyword=tablet", "keyword=tablet",
                        t, t.plusMillis(40), 200),
                new BenignSent(2, "/api/preview", "/api/preview?url=https%3A%2F%2Fwww.iana.org%2F", "url=https://www.iana.org/",
                        t.plusMillis(300), t.plusMillis(900), -1));
        BenignAlertLinker.Result linked = new BenignAlertLinker.Result(
                List.of(new BenignResult(1, "APP_RULE", List.of("100210"), List.of()),
                        new BenignResult(1, "NIDS", List.of(), List.of("1000030"))),
                List.of(new BenignUnlinkedAlert("NIDS", "1000060", t.plusSeconds(2), "NO_CANDIDATE")));

        new BenignRunRepository(DS).save(run, sent, Map.of(1, "rid-1"), linked);
        JDBC.update("UPDATE validation.measurement_run SET status = 'CLOSED', ended_at = now() WHERE run_id = ?", run);

        assertEquals(List.of("1|/api/products/search|200|rid-1", "2|/api/preview|-1|null"), JDBC.queryForList(
                "SELECT seq || '|' || endpoint || '|' || status || '|' || coalesce(matched_rid, 'null') "
                        + "FROM validation.benign_request WHERE run_id = ? ORDER BY seq", String.class, run));
        assertEquals(BenignRunRepository.sha256("keyword=tablet"), JDBC.queryForObject(
                "SELECT args_digest FROM validation.benign_request WHERE run_id = ? AND seq = 1", String.class, run));
        assertEquals(List.of("APP_RULE|true|1|{100210}|{}", "NIDS|false|0|{}|{1000030}"), JDBC.queryForList(
                "SELECT control || '|' || alerted || '|' || alert_count || '|' || linked_rule_ids::text || '|' "
                        + "|| recorded_rule_ids::text FROM validation.benign_result WHERE run_id = ? ORDER BY control",
                String.class, run));
        assertEquals(1, JDBC.queryForObject("SELECT count(*) FROM validation.benign_unlinked_alert WHERE run_id = ?",
                Integer.class, run));
        assertEquals("BENIGN_MATCH_MISMATCH", integrity(run).get("r10_reason"));
        assertEquals(List.of("NIDS|1000030|LINKED_RECORDED|1", "NIDS|1000060|UNLINKED_NO_CANDIDATE|1"),
                JDBC.queryForList("SELECT sensor || '|' || rule_id || '|' || kind || '|' || alerts FROM validation.v_metric_m14_rule "
                        + "WHERE run_id = ? AND sensor = 'NIDS' ORDER BY rule_id", String.class, run));
    }

    // ---- 스키마 ----

    @Test
    void benignTablesRejectAttackOrClosedRuns() {
        UUID attack = com.capstone.vuln.correlation.TestRuns.openTestRun(JDBC);
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status)
                VALUES (?, 1, '/api/preview', 'd', now(), now(), 200)""", attack));
        UUID closed = new BenignFixture(JDBC).close(0, true);
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status)
                VALUES (?, 1, '/api/preview', 'd', now(), now(), 200)""", closed));
        UUID open = new BenignFixture(JDBC).close(1, false);
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status)
                VALUES (?, 1, '/api/unknown', 'd', now(), now(), 200)""", open), "benign_endpoint 에 없는 엔드포인트");
    }
}
