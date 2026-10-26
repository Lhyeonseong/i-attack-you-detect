package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.ValidationDbFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static com.capstone.vuln.measure.MetricFixture.a;
import static com.capstone.vuln.measure.MetricFixture.rate;
import static com.capstone.vuln.measure.MetricFixture.xn;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T9 — 모든 V4 뷰는 kind = ATTACK(D7) ∧ attempt_role = ATTACK(R6) ∧ v_run_integrity.r10_status = VALID(R10) run 만.
 * 같은 데이터라도 INVALID(CLOSED, 기대 수 불일치)·INCOMPLETE(OPEN) run 은 어느 뷰에도 행이 없다.
 */
class MetricViewFilterTest extends ValidationDbFixture {

    static final List<String> VIEWS = List.of("v_metric_rates", "v_metric_mttd", "v_metric_correlation", "v_metric_h2",
            "v_metric_coverage", "v_metric_coverage_unit", "v_metric_attacker");

    @BeforeEach
    void clean() {
        truncateRunData();
    }

    private static int rows(String view, UUID run) {
        return JDBC.queryForObject("SELECT count(*) FROM validation." + view + " WHERE run_id = ?", Integer.class, run);
    }

    /** F1 + 링크 있는 시도 1건 (M05 뷰에도 행이 생길 데이터) */
    private static UUID f1WithLink(MetricFixture.Close close) {
        return MetricFixture.f1(JDBC)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"))
                .close(close);
    }

    @Test
    void validRunAppearsInEveryView() {
        UUID valid = f1WithLink(MetricFixture.Close.VALID);
        for (String v : VIEWS) {
            assertTrue(rows(v, valid) > 0, v);
        }
    }

    @Test
    void invalidAndIncompleteRunsHaveNoRows() {
        UUID invalid = f1WithLink(MetricFixture.Close.INVALID);
        UUID open = f1WithLink(MetricFixture.Close.OPEN);
        assertEquals("INVALID", JDBC.queryForObject(
                "SELECT r10_status FROM validation.v_run_integrity WHERE run_id = ?", String.class, invalid));
        assertEquals("INCOMPLETE", JDBC.queryForObject(
                "SELECT r10_status FROM validation.v_run_integrity WHERE run_id = ?", String.class, open));
        for (String v : VIEWS) {
            assertEquals(0, rows(v, invalid), v + " INVALID");
            assertEquals(0, rows(v, open), v + " INCOMPLETE");
        }
    }

    /**
     * D7: kind=BENIGN run 은 R10 VALID 이고 attempt_role=ATTACK verdict 가 있어도 공격 지표 뷰에 행이 없다 (M14 전용).
     * V7(ADR-S4-01 v1.8 R17 d)부터 BENIGN run 의 VALID = 기대 요청 수 = benign_request 적재 수 = 대조 수 —
     * OPEN 상태로 기대 수를 정한 뒤 그 수만큼 대조된 정상 요청을 넣고 닫는다.
     */
    @Test
    void benignRunHasNoRowsEvenWithAttackVerdicts() {
        MetricFixture fixture = MetricFixture.f1(JDBC).benign()
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").links("RID"));
        UUID benign = fixture.close(MetricFixture.Close.OPEN);
        int expected = JDBC.queryForObject("SELECT expected_attempts FROM validation.measurement_run WHERE run_id = ?",
                Integer.class, benign);
        for (int s = 1; s <= expected; s++) {
            JDBC.update("""
                    INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status,
                        matched_rid)
                    VALUES (?, ?, '/api/products/search', ?, now(), now(), 200, ?)""", benign, s, "d" + s, "rid-" + s);
        }
        com.capstone.vuln.correlation.TestRuns.closeTestRun(JDBC, benign);
        assertEquals("VALID", JDBC.queryForObject(
                "SELECT r10_status FROM validation.v_run_integrity WHERE run_id = ?", String.class, benign));
        for (String v : VIEWS) {
            assertEquals(0, rows(v, benign), v + " BENIGN");
        }
    }

    /** F1 의 CONTROL(SSRF FAILED_UNSEEN 1건)은 어느 지표에도 없다 */
    @Test
    void controlAttemptsAreNotCounted() {
        UUID run = MetricFixture.f1(JDBC).close(MetricFixture.Close.VALID);
        assertEquals("0/0", xn(rate(JDBC, run, "M07b", "SCENARIO", "SSRF")));
        assertEquals("0/0", xn(rate(JDBC, run, "M08", "SCENARIO", "SSRF")));
        assertEquals("1/11", xn(rate(JDBC, run, "M08", "ALL", "ALL")));
        assertEquals(0L, MetricFixture.l(JDBC.queryForMap(
                "SELECT n FROM validation.v_metric_attacker WHERE run_id = ? AND split_unit = 'SSRF'", run), "n"));
    }
}
