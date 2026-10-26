package com.capstone.vuln.product;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.evaluator.SqliResultType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqliValidatorTest {

    private SqliValidator validator;

    @BeforeEach
    void setUp() {
        SqliEvaluator evaluator = new SqliEvaluator();
        ReflectionTestUtils.setField(evaluator, "baselineLength", 1000L);
        ReflectionTestUtils.setField(evaluator, "lengthMultiplier", 3.0);
        ReflectionTestUtils.setField(evaluator, "timeThresholdMs", 3000L);
        validator = new SqliValidator(evaluator);
    }

    private static ValidationContext<SqliInput> ctx(SqliInput input) {
        return new ValidationContext<>("rid-1", null, Instant.now(), 200, input);
    }

    private static ValidationContext<SqliInput> normalCtx() {
        return ctx(SqliInput.ofRows(List.of(), 10, 2));
    }

    // --- SqliResultType 직접 주입: 매핑 검증 ---

    @Test
    void unionDataLeakedMapsToSucceededWithDataExposure() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.UNION_DATA_LEAKED);

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(EvidenceKind.DATA_EXPOSURE, singleEvidence(obs).kind());
        assertCommonFields(obs, SqliResultType.UNION_DATA_LEAKED);
    }

    @Test
    void sqlErrorExposedMapsToSucceededWithResponsePattern() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.SQL_ERROR_EXPOSED);

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(EvidenceKind.RESPONSE_PATTERN, singleEvidence(obs).kind());
        assertCommonFields(obs, SqliResultType.SQL_ERROR_EXPOSED);
    }

    @Test
    void timeBasedDelayMapsToExecutedWithTiming() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.TIME_BASED_DELAY);

        assertEquals(AttackOutcome.EXECUTED, obs.outcome());
        assertEquals(EvidenceKind.TIMING, singleEvidence(obs).kind());
        assertCommonFields(obs, SqliResultType.TIME_BASED_DELAY);
    }

    @Test
    void lengthAnomalyMapsToExecutedWithTiming() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.LENGTH_ANOMALY);

        assertEquals(AttackOutcome.EXECUTED, obs.outcome());
        assertEquals(EvidenceKind.TIMING, singleEvidence(obs).kind());
        assertCommonFields(obs, SqliResultType.LENGTH_ANOMALY);
    }

    @Test
    void normalMapsToFailed() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.NORMAL);

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, SqliResultType.NORMAL);
    }

    @Test
    void unknownMapsToUnknown() {
        AttackObservation obs = validator.observe(normalCtx(), SqliResultType.UNKNOWN);

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, SqliResultType.UNKNOWN);
    }

    // --- validate(): 기존 SqliEvaluator 위임 경로 ---

    @Test
    void validateUsesEvaluateNormalForRows() {
        List<Map<String, Object>> rows = List.of(Map.of("name", "$2a$10$abcdefghijklmnopqrstuv"));
        AttackObservation obs = validator.validate(ctx(SqliInput.ofRows(rows, 10, 50)));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(SqliResultType.UNION_DATA_LEAKED.name(), obs.resultType());
        // summary에 유출된 해시 원문이 들어가면 안 된다
        assertTrue(obs.evidence().stream().noneMatch(e -> e.summary().contains("$2a$")));
    }

    @Test
    void validateUsesEvaluateErrorForErrorMessage() {
        AttackObservation obs = validator.validate(
                ctx(SqliInput.ofError("PSQLException: ERROR: syntax error at or near \"'\"", 5)));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        assertEquals(SqliResultType.SQL_ERROR_EXPOSED.name(), obs.resultType());
    }

    @Test
    void validateReturnsUnknownWhenEvaluationThrows() {
        AttackObservation obs = validator.validate(ctx(new SqliInput(null, null, 10, 2)));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
    }

    @Test
    void techniqueIdComesFromCorrelationWhenPresent() {
        CorrelationInfo correlation = new CorrelationInfo("op-1", "T1059", "ab-1",
                CorrelationSource.HEADER, "10.0.0.1", "ua");
        ValidationContext<SqliInput> ctx = new ValidationContext<>(
                "rid-2", correlation, Instant.now(), 200, SqliInput.ofRows(List.of(), 10, 2));

        AttackObservation obs = validator.validate(ctx);

        assertEquals("T1059", obs.techniqueId());
        assertEquals(correlation, obs.correlation());
    }

    private static Evidence singleEvidence(AttackObservation obs) {
        assertEquals(1, obs.evidence().size());
        return obs.evidence().get(0);
    }

    private static void assertCommonFields(AttackObservation obs, SqliResultType resultType) {
        assertEquals("rid-1", obs.rid());
        assertEquals(AttackScenario.SQLI, obs.scenario());
        assertEquals(SqliValidator.DEFAULT_TECHNIQUE_ID, obs.techniqueId());
        assertEquals(resultType.name(), obs.resultType());
        assertEquals("v1", obs.validatorVersion());
    }
}
