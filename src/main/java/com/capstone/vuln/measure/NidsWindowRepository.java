package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * validation.nids_window_stat — op 창 1개의 NIDS 집계(R14 b orphan·R14 d 분류별 수·R14 c http 연결 수).
 * 같은 (run, op) 를 다시 측정하면 덮어쓴다(파생 기록). run 별 합계는 v_nids_run_stat.
 * 행 존재 = 그 run 은 NIDS·텔레메트리를 수집했다(R15 NOT_COLLECTED 판별).
 */
public class NidsWindowRepository {

    private final JdbcTemplate jdbc;

    public NidsWindowRepository(DataSource validationDataSource) {
        this.jdbc = new JdbcTemplate(validationDataSource);
    }

    public void save(UUID runId, String opId, Instant windowStart, Instant windowEnd, NidsWindowCounts c) {
        jdbc.update("""
                INSERT INTO validation.nids_window_stat (run_id, op_id, window_start, window_end, nids_alerts,
                    orphan_alerts, analytic_alerts, analytic_linked, telemetry_alerts, marker_alerts, undecided_alerts,
                    unclassified_alerts, http_events, http_attributed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (run_id, op_id) DO UPDATE SET
                    window_start = EXCLUDED.window_start, window_end = EXCLUDED.window_end,
                    nids_alerts = EXCLUDED.nids_alerts, orphan_alerts = EXCLUDED.orphan_alerts,
                    analytic_alerts = EXCLUDED.analytic_alerts, analytic_linked = EXCLUDED.analytic_linked,
                    telemetry_alerts = EXCLUDED.telemetry_alerts, marker_alerts = EXCLUDED.marker_alerts,
                    undecided_alerts = EXCLUDED.undecided_alerts, unclassified_alerts = EXCLUDED.unclassified_alerts,
                    http_events = EXCLUDED.http_events, http_attributed = EXCLUDED.http_attributed,
                    recorded_at = now()""",
                runId, opId, windowStart.atOffset(ZoneOffset.UTC), windowEnd.atOffset(ZoneOffset.UTC),
                c.nidsAlerts(), c.orphanAlerts(), c.analyticAlerts(), c.analyticLinked(), c.telemetryAlerts(),
                c.markerAlerts(), c.undecidedAlerts(), c.unclassifiedAlerts(), c.httpEvents(), c.httpAttributed());
    }
}
