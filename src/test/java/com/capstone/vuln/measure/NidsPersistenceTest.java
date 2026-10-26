package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.OperationLink;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.TestRuns;
import com.capstone.vuln.correlation.ValidationDbFixture;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 하네스 관통 (R14·R15): op 창 1개 → detection_link.control, telemetry_observation, nids_window_stat 저장.
 * 앱 이벤트 PT 2건(passwd·hosts), 앱 룰 alert 100220 1건(passwd), Suricata alert 3건
 * (ANALYTIC 1000020 passwd · MARKER 1000001 passwd · ANALYTIC 1000020 연결 http 없음 = orphan), eve http 2건.
 */
class NidsPersistenceTest extends ValidationDbFixture {

    private static final Instant T0 = Instant.parse("2026-10-21T10:00:00Z");
    private static final String PAW = "eiwwvn";
    private static final String PT = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String OP = "8378c817-4f95-42a8-84d4-031f6a5ca173";
    private static final String UA = "Caldera/" + PAW + "/T1190/" + PT;

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    private static final class FixedCollector extends MeasurementCollector {
        private final CollectedWindow window;

        FixedCollector(CollectedWindow window) {
            super(null, null, null, Duration.ZERO);
            this.window = window;
        }

        @Override
        public CollectedWindow collect(String opId, Instant attackTime, Instant opFinish) {
            return window;
        }
    }

    private static AttackEvent pt(String rid, long ms) {
        return new AttackEvent(new CorrelationKey(PAW, PT, rid), "PATH_TRAVERSAL", "T1190", T0.plusMillis(ms),
                "172.20.0.1", "/api/files/download", null, GroundTruthOutcome.SUCCEEDED);
    }

    private static CollectedWindow window() {
        List<AttackEvent> attacks = List.of(pt("rid-passwd", 1_000), pt("rid-hosts", 1_200));
        AlertEvent appRule = new AlertEvent("100220", "T1190", T0.plusMillis(2_000), null, "rid-passwd", PAW, PT,
                "172.20.0.1", "/api/files/download", CorrelationSource.HEADER);
        List<NidsAlert> nids = List.of(
                new NidsAlert(1000020, T0.plusMillis(2_400), null, 11L, 0L, "172.20.0.1"),
                new NidsAlert(1000001, T0.plusMillis(2_400), null, 11L, 0L, "172.20.0.1"),
                new NidsAlert(1000020, T0.plusMillis(2_500), null, 99L, 0L, "172.20.0.1"));
        List<EveHttp> http = List.of(
                new EveHttp(11, 0, T0.plusMillis(1_010), "/api/files/download?filename=../../../../etc/passwd", UA,
                        "172.20.0.1", "172.20.0.3", 8080),
                new EveHttp(12, 0, T0.plusMillis(1_210), "/api/files/download?filename=../../../../etc/hosts", UA,
                        "172.20.0.1", "172.20.0.3", 8080));
        Map<String, String> args = Map.of("rid-passwd", "filename=../../../../etc/passwd",
                "rid-hosts", "filename=../../../../etc/hosts");
        return new CollectedWindow(attacks, List.of(appRule), Map.of(), Map.of(), nids, http, args);
    }

    private static OperationResolver caldera() {
        return new OperationResolver(() -> List.of(new OperationLink(OP, PAW, PT, T0, T0.plusSeconds(10))));
    }

    @Test
    void harnessStoresControlTelemetryAndWindowStat() {
        UUID run = TestRuns.openTestRun(JDBC);
        MeasurementHarness harness = new MeasurementHarness(new FixedCollector(window()), new CorrelationEngine(),
                new VerdictEngine(), new VerdictRepository(DS), caldera(),
                new NidsCorrelator(NidsSidCatalog.V1_7), new NidsWindowRepository(DS));

        harness.measure(run, OP, T0, T0.plusSeconds(5));

        List<Map<String, Object>> links = JDBC.queryForList("""
                SELECT c.rid, l.rule_id, l.control, l.match_path, l.confidence, l.technique
                FROM validation.detection_link l JOIN validation.correlation c ON c.id = l.correlation_id
                ORDER BY c.rid, l.control""");
        assertEquals(2, links.size(), links.toString());
        assertEquals(List.of("rid-passwd", "100220", "APP_RULE", "RID", 1.0, "T1190"),
                List.copyOf(links.get(0).values()));
        assertEquals(List.of("rid-passwd", "1000020", "NIDS", "UA_FALLBACK", 0.7, "T1190"),
                List.copyOf(links.get(1).values()));

        List<String> telemetry = JDBC.queryForList("""
                SELECT c.rid || ':' || t.sensor || '=' || t.event_count
                FROM validation.telemetry_observation t
                JOIN validation.verdict_member m ON m.verdict_id = t.verdict_id
                JOIN validation.correlation c ON c.id = m.correlation_id
                WHERE t.run_id = ? ORDER BY 1""", String.class, run);
        assertEquals(List.of("rid-hosts:APP_LOG=1", "rid-hosts:NIDS=1", "rid-passwd:APP_LOG=1", "rid-passwd:NIDS=1"),
                telemetry);

        Map<String, Object> stat = JDBC.queryForMap("SELECT * FROM validation.nids_window_stat WHERE run_id = ?", run);
        assertEquals(OP, stat.get("op_id"));
        assertEquals(3, stat.get("nids_alerts"));
        assertEquals(1, stat.get("orphan_alerts"));
        assertEquals(2, stat.get("analytic_alerts"));
        assertEquals(1, stat.get("analytic_linked"));
        assertEquals(1, stat.get("marker_alerts"));
        assertEquals(2, stat.get("http_events"));
        assertEquals(2, stat.get("http_attributed"));
    }

    /** 기존 저장 경로(NIDS 없음)는 control = APP_RULE, 텔레메트리·창 기록 없음 — R14 이전 동작 그대로 */
    @Test
    void legacyHarnessWithoutNidsKeepsAppRuleOnly() {
        UUID run = TestRuns.openTestRun(JDBC);
        MeasurementHarness harness = new MeasurementHarness(new FixedCollector(window()), new CorrelationEngine(),
                new VerdictEngine(), new VerdictRepository(DS), caldera());

        harness.measure(run, OP, T0, T0.plusSeconds(5));

        assertEquals(List.of("APP_RULE"), JDBC.queryForList(
                "SELECT DISTINCT control FROM validation.detection_link", String.class));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.telemetry_observation", Integer.class));
        assertEquals(0, JDBC.queryForObject("SELECT count(*) FROM validation.nids_window_stat", Integer.class));
    }

    /** NIDS 링크는 UA_FALLBACK 만(R14 c), telemetry 의 run_id 는 verdict 의 run 과 같아야 한다 */
    @Test
    void schemaRejectsInconsistentNidsRows() {
        UUID run = TestRuns.openTestRun(JDBC);
        UUID other = TestRuns.openTestRun(JDBC);
        TestRuns.insertVerdict(JDBC, run, "unit:x", "ATTACK");
        long verdictId = JDBC.queryForObject("SELECT id FROM validation.verdict_result WHERE unit_key = 'unit:x'",
                Long.class);
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.telemetry_observation (run_id, verdict_id, sensor, event_count)
                VALUES (?, ?, 'NIDS', 1)""", other, verdictId));

        long correlationId = JDBC.queryForObject("""
                INSERT INTO validation.correlation (correlation_key, op_id_resolved, scenario, attack_time,
                    last_attack_time, observed_until, best_confidence, correlation_source, bf_failure_count,
                    bf_sequence, spray, spray_account_count)
                VALUES ('k', false, 'SQLI', now(), now(), now(), 1.0, 'RID', 0, false, false, 0) RETURNING id""",
                Long.class);
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.detection_link (correlation_id, rule_id, alert_time, match_path, confidence,
                    late, control)
                VALUES (?, '1000013', now(), 'RID', 1.0, false, 'NIDS')""", correlationId));
        assertThrows(Exception.class, () -> JDBC.update("""
                INSERT INTO validation.detection_link (correlation_id, rule_id, alert_time, match_path, confidence,
                    late)
                VALUES (?, '100210', now(), 'RID', 1.0, false)""", correlationId), "control 은 NOT NULL");
    }
}
