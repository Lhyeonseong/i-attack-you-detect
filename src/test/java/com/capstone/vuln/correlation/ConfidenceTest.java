package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfidenceTest {

    private static final Instant ALERT_TIME = Instant.parse("2026-10-13T00:00:10Z");

    private static DetectionLink link(MatchPath path) {
        return DetectionLink.of("100240", "T1190", ALERT_TIME, path);
    }

    @Test
    void eachMatchPathMapsToItsConfidenceValue() {
        assertEquals(1.0, Confidence.of(MatchPath.RID).value());
        assertEquals(0.9, Confidence.of(MatchPath.HEADER).value());
        assertEquals(0.7, Confidence.of(MatchPath.UA_FALLBACK).value());
        assertEquals(0.3, Confidence.of(MatchPath.TIME_ONLY).value());
    }

    @Test
    void onlyPathsAtOrAboveThresholdAreUsableForVerdict() {
        assertTrue(Confidence.of(MatchPath.RID).usableForVerdict());
        assertTrue(Confidence.of(MatchPath.HEADER).usableForVerdict());
        assertTrue(Confidence.of(MatchPath.UA_FALLBACK).usableForVerdict());
        assertFalse(Confidence.of(MatchPath.TIME_ONLY).usableForVerdict());
    }

    @Test
    void bestLinkWinsAndHeaderLevelResolvesToHeaderSource() {
        ConfidenceResolver.Resolution r = ConfidenceResolver.resolve(
                List.of(link(MatchPath.TIME_ONLY), link(MatchPath.HEADER)));

        assertEquals(0.9, r.bestConfidence());
        assertEquals(MatchSource.HEADER, r.source());
    }

    @Test
    void timeOnlyLinkResolvesToNoneSource() {
        ConfidenceResolver.Resolution r = ConfidenceResolver.resolve(
                List.of(link(MatchPath.TIME_ONLY)));

        assertEquals(0.3, r.bestConfidence());
        assertEquals(MatchSource.NONE, r.source());
    }

    @Test
    void noLinksResolvesToZeroAndNoneSource() {
        ConfidenceResolver.Resolution r = ConfidenceResolver.resolve(List.of());

        assertEquals(0.0, r.bestConfidence());
        assertEquals(MatchSource.NONE, r.source());
    }
}
