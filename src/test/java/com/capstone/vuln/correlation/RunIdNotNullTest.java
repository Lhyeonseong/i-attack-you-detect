package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** T5 — verdict_result.run_id NOT NULL (ADR-S4-01 R10: 모든 verdict 는 하나의 run 에 귀속) */
class RunIdNotNullTest extends ValidationDbFixture {

    @Test
    void verdictWithoutRunIsRejected() {
        DataAccessException e = assertThrows(DataAccessException.class, () -> TestRuns.insertVerdict(JDBC, null, "unit:orphan", "ATTACK"));
        String msg = e.getMostSpecificCause().getMessage();
        assertTrue(msg.contains("run_id") && msg.contains("not-null"), msg);
        assertEquals("NO", JDBC.queryForObject("""
                SELECT is_nullable FROM information_schema.columns
                WHERE table_schema = 'validation' AND table_name = 'verdict_result' AND column_name = 'run_id'""",
                String.class));
    }
}
