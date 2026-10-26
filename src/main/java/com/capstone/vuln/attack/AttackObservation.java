package com.capstone.vuln.attack;

import com.capstone.vuln.correlation.CorrelationInfo;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * 공격 1건에 대한 Validator의 관찰 결과
 * - 규칙: outcome이 SUCCEEDED면 evidence가 최소 1개 있어야 한다
 */
public record AttackObservation(
        String rid,
        AttackScenario scenario,
        String techniqueId,
        AttackOutcome outcome,
        String resultType,
        List<Evidence> evidence,
        String reason,
        CorrelationInfo correlation,
        Instant observedAt,
        String validatorVersion) {

    public AttackObservation {
        Objects.requireNonNull(scenario, "scenario");
        Objects.requireNonNull(outcome, "outcome");
        evidence = evidence == null ? List.of() : List.copyOf(evidence);

        if (outcome == AttackOutcome.SUCCEEDED && evidence.isEmpty()) {
            throw new IllegalArgumentException("SUCCEEDED outcome requires at least one evidence");
        }
    }
}
