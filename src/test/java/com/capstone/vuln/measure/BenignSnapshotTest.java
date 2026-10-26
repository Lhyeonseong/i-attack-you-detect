package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.l;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V7 — M14b 짝 run(R18 e)과 BENIGN 스냅샷(R18 h). 스냅샷이 불변 행을 남기므로 이 클래스 전용 컨테이너.
 * 짝 ATTACK run 링크(손계산): APP_RULE conf ≥ 0.7·technique 일치 3건, NIDS ANALYTIC 2건(MARKER 1건은 제외).
 */
class BenignSnapshotTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        JDBC = new JdbcTemplate(ValidationDbFixture.bootstrap(PG));
    }

    private static final String DIGEST = "{\"wazuh_rules\":\"w\",\"suricata_rules\":\"s\"}";

    private static UUID attackRun(String digest, boolean nids, boolean snapshot, String startedAt) {
        MetricFixture f = new MetricFixture(JDBC);
        if (nids) {
            f.nidsCollected();
        }
        UUID run = f.add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100220").ctl("NIDS", "1000020"))
                .add(a("SSRF", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100240").ctl("NIDS", "1000060")
                        .ctl("NIDS", "1000001"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100210"))
                .close(MetricFixture.Close.VALID);
        JDBC.update("UPDATE validation.measurement_run SET rules_digest = ?::jsonb, started_at = ?::timestamptz "
                + "WHERE run_id = ?", digest, startedAt, run);
        if (snapshot) {
            JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        }
        return run;
    }

    private static UUID webRun(String digest) {
        return new BenignFixture(JDBC, digest)
                .requests("/api/products/search", 300, 300, 0, 0)
                .requests("/api/files/download", 300, 300, 3, 0)
                .requests("/api/preview", 300, 300, 0, 6)
                .close(900, true);
    }

    private static Map<String, Object> m14b(UUID run, String control) {
        return JDBC.queryForMap("SELECT * FROM validation.v_metric_m14b WHERE run_id = ? AND metric_id = ?",
                run, "M14b_" + control);
    }

    /**
     * 짝 = 같은 digest 의 VALID ATTACK run 중 스냅샷이 있는 가장 최근 run (스냅샷 없는 더 최근 run 은 짝이 아님).
     * APP_RULE FP 3 / (3 + TP 3) = 3/6, NIDS FP 6 / (6 + TP 2) = 6/8.
     */
    @Test
    void m14bPairsWithLatestSnapshottedRunAndSnapshotStoresM14() {
        attackRun(DIGEST, true, true, "2026-10-20T00:00:00Z");
        UUID pair = attackRun(DIGEST, true, true, "2026-10-21T00:00:00Z");
        attackRun(DIGEST, true, false, "2026-10-21T12:00:00Z");
        UUID web = webRun(DIGEST);

        Map<String, Object> app = m14b(web, "APP_RULE");
        assertEquals(pair, app.get("paired_run_id"));
        assertEquals(3L, l(app, "x"));
        assertEquals(6L, l(app, "n"));
        assertEquals("OK", app.get("status"));
        Map<String, Object> nids = m14b(web, "NIDS");
        assertEquals(6L, l(nids, "x"));
        assertEquals(8L, l(nids, "n"));
        assertEquals("NO_RULE", m14b(web, "BACKEND_CORR").get("status"), "BACKEND_CORR × 웹 = NO_RULE (R18 b, M13·M14a 와 같은 규칙)");

        int rows = JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, web);
        assertEquals(12, rows, "M14a 엔드포인트 3 × 통제 3 + M14b 통제 3");
        List<Map<String, Object>> snap = JDBC.queryForList(
                "SELECT * FROM validation.metric_snapshot WHERE run_id = ? ORDER BY metric_id, scope_key", web);
        snap.forEach(r -> assertEquals("ADR-S4-01 v2.0", r.get("definition_version")));
        snap.forEach(r -> assertEquals("ADR-S4-01 v1.8", r.get("snapshot_rule_version")));
        Map<String, Object> s = snap.stream().filter(r -> "M14b_APP_RULE".equals(r.get("metric_id"))).findFirst()
                .orElseThrow();
        assertEquals(pair, s.get("paired_run_id"));
        assertEquals(3L, l(s, "numerator"));
        assertEquals(6L, l(s, "denominator"));
        assertEquals("ALL", s.get("scope_kind"));
        Map<String, Object> a = snap.stream().filter(r -> "M14a_APP_RULE".equals(r.get("metric_id"))
                && "PATH_TRAVERSAL".equals(r.get("scope_key"))).findFirst().orElseThrow();
        assertEquals(3L, l(a, "numerator"));
        assertEquals(300L, l(a, "denominator"));
        assertEquals("SCENARIO", a.get("scope_kind"));
        assertNull(a.get("paired_run_id"));

        DataAccessException dup = assertThrows(DataAccessException.class,
                () -> JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, web));
        assertTrue(dup.getMostSpecificCause().getMessage().contains("이미"), dup.getMostSpecificCause().getMessage());
    }

    /** 짝 run 이 NIDS 를 수집하지 않았으면(R15) NIDS 는 NOT_COLLECTED, APP_RULE 은 계산 */
    @Test
    void pairWithoutNidsCollectionIsNotCollectedForNids() {
        String digest = "{\"wazuh_rules\":\"w2\"}";
        UUID pair = attackRun(digest, false, true, "2026-10-21T00:00:00Z");
        UUID web = webRun(digest);

        assertEquals("NOT_COLLECTED", m14b(web, "NIDS").get("status"));
        assertNull(m14b(web, "NIDS").get("x"));
        assertEquals(pair, m14b(web, "APP_RULE").get("paired_run_id"));
        assertEquals("OK", m14b(web, "APP_RULE").get("status"));
    }

    @Test
    void invalidBenignRunSnapshotIsRefused() {
        UUID run = new BenignFixture(JDBC).requests("/api/preview", 3, 2, 0, 0).close(3, true);
        DataAccessException e = assertThrows(DataAccessException.class,
                () -> JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run));
        assertTrue(e.getMostSpecificCause().getMessage().contains("BENIGN_MATCH_MISMATCH"),
                e.getMostSpecificCause().getMessage());
    }
}
