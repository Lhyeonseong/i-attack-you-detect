package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S4-3 truncate 경로 — metric_snapshot 에 행이 있으면 GateVerdictReader.truncateAll 이 아무것도 지우지 않고 거부한다
 * (CLOSED run 거부와 같은 방식). CLOSED 검사와 따로 보려고 스냅샷 뒤 run 을 OPEN 으로 되돌린다.
 * 스냅샷 행은 지울 수 없으므로 전용 컨테이너를 쓴다.
 */
class MetricSnapshotTruncateGuardTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG);
        JDBC = new JdbcTemplate(DS);
    }

    private static int count(String table) {
        return JDBC.queryForObject("SELECT count(*) FROM validation." + table, Integer.class);
    }

    @Test
    void truncateIsRefusedWhileSnapshotRowsExistAndNothingIsDeleted() {
        UUID run = new MetricFixture(JDBC).add(a("SQLI", "T1190", "SUCCEEDED_DETECTED")).close(MetricFixture.Close.VALID);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, run);
        // CLOSED run 거부와 구분: run 을 OPEN 으로 되돌려 CLOSED run 0개로 만든다
        JDBC.update("UPDATE validation.measurement_run SET status = 'OPEN', ended_at = NULL WHERE run_id = ?", run);
        int verdicts = count("verdict_result");
        int snapshots = count("metric_snapshot");

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> new GateVerdictReader(DS).truncateAll());

        assertTrue(e.getMessage().contains("metric_snapshot"), e.getMessage());
        assertEquals(verdicts, count("verdict_result"));
        assertEquals(snapshots, count("metric_snapshot"));
    }
}
