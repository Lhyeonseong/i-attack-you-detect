package com.capstone.vuln.attack;

import com.capstone.vuln.attack.Evidence.EvidenceKind;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AttackObservationTest {

    private static AttackObservation observation(AttackOutcome outcome, List<Evidence> evidence) {
        return new AttackObservation("rid-1", AttackScenario.SQLI, "T1190", outcome, "X",
                evidence, "reason", null, Instant.now(), "v1");
    }

    @Test
    void succeededWithEmptyEvidenceThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> observation(AttackOutcome.SUCCEEDED, List.of()));
    }

    @Test
    void succeededWithNullEvidenceThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> observation(AttackOutcome.SUCCEEDED, null));
    }

    @Test
    void succeededWithEvidenceIsAllowed() {
        Evidence evidence = new Evidence(EvidenceKind.RESPONSE_PATTERN, "pattern matched", "fp");
        assertDoesNotThrow(() -> observation(AttackOutcome.SUCCEEDED, List.of(evidence)));
    }

    @Test
    void nonSucceededWithoutEvidenceIsAllowed() {
        assertDoesNotThrow(() -> observation(AttackOutcome.FAILED, List.of()));
        assertDoesNotThrow(() -> observation(AttackOutcome.UNKNOWN, null));
    }
}
