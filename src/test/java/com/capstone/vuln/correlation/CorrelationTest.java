package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationTest {

    @Test
    void observedUntilIsAttackTimePlusThirtySecondsAndStartsUnjudged() {
        Instant attackTime = Instant.parse("2026-10-13T00:00:00Z");
        Correlation c = new Correlation(
                new CorrelationKey("op-1", "a7f3c1d9", "rid-1"),
                "SSRF", "T1190", attackTime, "10.0.0.5");

        assertEquals(Instant.parse("2026-10-13T00:00:30Z"), c.getObservedUntil());
        assertNull(c.getVerdict());
        assertNull(c.getMttdMs());
        assertTrue(c.getLinks().isEmpty());
        assertEquals(MatchSource.NONE, c.getCorrelationSource());
    }
}
