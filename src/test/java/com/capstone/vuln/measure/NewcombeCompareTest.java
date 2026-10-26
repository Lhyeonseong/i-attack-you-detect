package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.PostgresTestImage;
import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * V10 newcombe_diff_ci·compare_snapshots (ADR-S5-01). 경계값은 구현과 독립으로 손 계산한 기대(Newcombe method 10, z=1.959964),
 * 허용오차 1e-6. (x1,n1)=after, (x2,n2)=before. 전용 컨테이너(스냅샷 불변 행).
 */
class NewcombeCompareTest {

    private static final PostgreSQLContainer<?> PG = new PostgreSQLContainer<>(PostgresTestImage.IMAGE);
    private static final DataSource DS;
    private static final JdbcTemplate JDBC;

    static {
        PG.start();
        DS = ValidationDbFixture.bootstrap(PG);
        JDBC = new JdbcTemplate(DS);
    }

    private static final double EPS = 1e-6;

    private Map<String, Object> nc(long x1, long n1, long x2, long n2) {
        return JDBC.queryForMap("SELECT diff, lo, hi FROM validation.newcombe_diff_ci(?, ?, ?, ?)", x1, n1, x2, n2);
    }

    private static void assertCi(Map<String, Object> r, double diff, double lo, double hi) {
        assertEquals(diff, ((Number) r.get("diff")).doubleValue(), EPS);
        assertEquals(lo, ((Number) r.get("lo")).doubleValue(), EPS);
        assertEquals(hi, ((Number) r.get("hi")).doubleValue(), EPS);
    }

    @Test
    void newcombeBoundaryValues() {
        assertCi(nc(0, 20, 20, 20), -1.000000, -1.000000, -0.772135);
        assertCi(nc(2, 20, 20, 20), -0.900000, -0.972134, -0.642365);
        assertCi(nc(16, 20, 20, 20), -0.200000, -0.416017, 0.000509);
        assertCi(nc(0, 320, 0, 320), 0.000000, -0.011862, 0.011862);
        assertCi(nc(4, 320, 0, 320), 0.012500, -0.001603, 0.031694);
        assertCi(nc(5, 320, 0, 320), 0.015625, 0.000775, 0.036049);
        assertCi(nc(3, 10, 1, 10), 0.200000, -0.159794, 0.514146);
    }

    @Test
    void nZeroGivesNull() {
        Map<String, Object> a = nc(0, 0, 1, 10);
        assertNull(a.get("diff"));
        assertNull(a.get("lo"));
        assertNull(a.get("hi"));
        Map<String, Object> b = nc(1, 10, 0, 0);
        assertNull(b.get("diff"));
    }

    /** compare_snapshots: 두 VALID ATTACK run 스냅샷을 metric×scope 로 묶어 diff. 같은 뷰라 definition_version 일치. */
    @Test
    void compareSnapshotsJoinsByMetricAndScope() {
        UUID before = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100210"))
                .close(MetricFixture.Close.VALID);
        UUID after = new MetricFixture(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100211"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100211"))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").ctl("APP_RULE", "100211"))
                .close(MetricFixture.Close.VALID);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, before);
        JDBC.queryForObject("SELECT validation.take_metric_snapshot(?)", Integer.class, after);

        // 비율 지표만: numerator(x) 가 NULL 인 행(M04 MTTD 등 — denominator=n, numerator NULL)은 Newcombe 대상이 아니다
        List<Map<String, Object>> rows = JDBC.queryForList(
                "SELECT * FROM validation.compare_snapshots(?, ?) WHERE n1 > 0 AND n2 > 0 "
                        + "AND x1 IS NOT NULL AND x2 IS NOT NULL", before, after);
        assertTrue(rows.size() > 0, "묶인 비율 metric 행이 있어야 한다");
        // 각 행의 diff·lo·hi 는 그 행의 (x1,n1,x2,n2)로 부른 newcombe_diff_ci 와 같아야 한다(방향·배선 확인)
        for (Map<String, Object> r : rows) {
            long x1 = ((Number) r.get("x1")).longValue(), n1 = ((Number) r.get("n1")).longValue();
            long x2 = ((Number) r.get("x2")).longValue(), n2 = ((Number) r.get("n2")).longValue();
            Map<String, Object> expect = nc(x1, n1, x2, n2);
            if (r.get("diff") == null) {
                assertNull(expect.get("diff"));
                continue;
            }
            assertEquals(((Number) expect.get("diff")).doubleValue(), ((Number) r.get("diff")).doubleValue(), EPS);
            assertEquals(((Number) expect.get("lo")).doubleValue(), ((Number) r.get("lo")).doubleValue(), EPS);
            assertEquals(((Number) expect.get("hi")).doubleValue(), ((Number) r.get("hi")).doubleValue(), EPS);
        }
        // M03 SQLI(miss rate): before 2/3, after 0/3 → diff 음수(미탐 감소)
        Map<String, Object> m03 = rows.stream()
                .filter(r -> "M03".equals(r.get("metric_id")) && "SCENARIO".equals(r.get("scope_kind"))
                        && "SQLI".equals(r.get("scope_key"))).findFirst().orElseThrow();
        assertTrue(((Number) m03.get("diff")).doubleValue() < 0, "SQLI Miss Rate After−Before < 0");
    }
}
