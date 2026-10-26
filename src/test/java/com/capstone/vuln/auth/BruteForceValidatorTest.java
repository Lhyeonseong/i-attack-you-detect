package com.capstone.vuln.auth;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.auth.BruteForceInput.ResultType;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BruteForceValidatorTest {

    private final BruteForceValidator validator = new BruteForceValidator();

    private static ValidationContext<BruteForceInput> ctx(ResultType resultType) {
        return new ValidationContext<>("rid-1", null, Instant.now(), 200, new BruteForceInput(resultType));
    }

    @Test
    void authSuccessMapsToSucceededWithCredentialValid() {
        AttackObservation obs = validator.validate(ctx(ResultType.AUTH_SUCCESS));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(EvidenceKind.CREDENTIAL_VALID, singleEvidence(obs).kind());
        assertCommonFields(obs, ResultType.AUTH_SUCCESS);
    }

    @Test
    void authFailMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(ResultType.AUTH_FAIL));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.AUTH_FAIL);
    }

    @Test
    void dbErrorMapsToUnknown() {
        AttackObservation obs = validator.validate(ctx(ResultType.DB_ERROR));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.DB_ERROR);
    }

    @Test
    void validateReturnsUnknownWhenEvaluationThrows() {
        AttackObservation obs = validator.validate(
                new ValidationContext<>("rid-1", null, Instant.now(), 200, new BruteForceInput(null)));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertEquals("UNKNOWN", obs.resultType());
    }

    @Test
    void techniqueIdComesFromCorrelationWhenPresent() {
        CorrelationInfo correlation = new CorrelationInfo("op-1", "T1110.001", "ab-1",
                CorrelationSource.HEADER, "10.0.0.1", "ua");
        ValidationContext<BruteForceInput> ctx = new ValidationContext<>(
                "rid-2", correlation, Instant.now(), 401, new BruteForceInput(ResultType.AUTH_FAIL));

        AttackObservation obs = validator.validate(ctx);

        assertEquals("T1110.001", obs.techniqueId());
        assertEquals(correlation, obs.correlation());
    }

    private static Evidence singleEvidence(AttackObservation obs) {
        assertEquals(1, obs.evidence().size());
        return obs.evidence().get(0);
    }

    private static void assertCommonFields(AttackObservation obs, ResultType resultType) {
        assertEquals("rid-1", obs.rid());
        assertEquals(AttackScenario.BRUTE_FORCE, obs.scenario());
        assertEquals(BruteForceValidator.DEFAULT_TECHNIQUE_ID, obs.techniqueId());
        assertEquals(resultType.name(), obs.resultType());
        assertEquals("v1", obs.validatorVersion());
    }
}
