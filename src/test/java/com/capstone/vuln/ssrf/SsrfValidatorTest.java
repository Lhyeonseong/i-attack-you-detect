package com.capstone.vuln.ssrf;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.ssrf.SsrfInput.ResultType;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SsrfValidatorTest {

    private final SsrfValidator validator = new SsrfValidator();

    private static ValidationContext<SsrfInput> ctx(SsrfInput input) {
        return new ValidationContext<>("rid-1", null, Instant.now(), 200, input);
    }

    @Test
    void internalMetadataReachedMapsToSucceededWithMetadataReached() {
        AttackObservation obs = validator.validate(ctx(SsrfInput.fetched(
                true, true, "169.254.169.254", 200, 40)));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        Evidence evidence = singleEvidence(obs);
        assertEquals(EvidenceKind.METADATA_REACHED, evidence.kind());
        // summary 에 응답 본문/자격증명 원문이 들어가면 안 된다
        assertFalse(evidence.summary().contains("mock-iam-role"));
        assertFalse(evidence.summary().contains("MOCK-IMDS-DO-NOT-USE"));
        assertCommonFields(obs, ResultType.FETCHED);
    }

    @Test
    void internalTargetWithoutSentinelStillSucceeds() {
        // 내부 대역에 도달했으면 sentinel 이 없어도 SSRF 성립 (예: 다른 내부 서비스)
        AttackObservation obs = validator.validate(ctx(SsrfInput.fetched(
                true, false, "127.0.0.1", 200, 120)));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(EvidenceKind.METADATA_REACHED, singleEvidence(obs).kind());
    }

    @Test
    void externalPublicFetchMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(SsrfInput.fetched(
                false, false, "example.com", 200, 1500)));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.FETCHED);
    }

    @Test
    void whitelistBlockedMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(SsrfInput.blocked("file")));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.BLOCKED);
    }

    @Test
    void connectionErrorMapsToUnknown() {
        AttackObservation obs = validator.validate(ctx(SsrfInput.error("10.0.0.9")));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.ERROR);
    }

    @Test
    void validateReturnsUnknownWhenEvaluationThrows() {
        // resultType=null 이면 switch 에서 NPE -> UNKNOWN 로 흡수
        AttackObservation obs = validator.validate(ctx(new SsrfInput(
                null, true, true, "169.254.169.254", 200, 10)));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertEquals("UNKNOWN", obs.resultType());
    }

    @Test
    void techniqueIdComesFromCorrelationWhenPresent() {
        CorrelationInfo correlation = new CorrelationInfo("op-1", "T1090", "ab-1",
                CorrelationSource.HEADER, "10.0.0.1", "ua");
        ValidationContext<SsrfInput> ctx = new ValidationContext<>(
                "rid-2", correlation, Instant.now(), 200,
                SsrfInput.fetched(true, true, "169.254.169.254", 200, 40));

        AttackObservation obs = validator.validate(ctx);

        assertEquals("T1090", obs.techniqueId());
        assertEquals(correlation, obs.correlation());
    }

    private static Evidence singleEvidence(AttackObservation obs) {
        assertEquals(1, obs.evidence().size());
        return obs.evidence().get(0);
    }

    private static void assertCommonFields(AttackObservation obs, ResultType resultType) {
        assertEquals("rid-1", obs.rid());
        assertEquals(AttackScenario.SSRF, obs.scenario());
        assertEquals(SsrfValidator.DEFAULT_TECHNIQUE_ID, obs.techniqueId());
        assertEquals(resultType.name(), obs.resultType());
        assertEquals("v1", obs.validatorVersion());
    }
}
