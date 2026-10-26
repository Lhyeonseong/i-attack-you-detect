package com.capstone.vuln.auth;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.AttackValidator;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.auth.BruteForceInput.ResultType;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * Brute Force 요청 단위 판정기
 * - AuthController의 기존 result_type -> AttackOutcome 매핑만 담당 (lockout 부재 로직에는 관여하지 않음)
 * - AUTH_SUCCESS는 "이 요청의 자격증명이 유효했다"는 뜻일 뿐 BF 성공 자체가 아니다.
 *   실패 N회 후 성공 같은 다단계 판정은 탐지/상관(Wazuh 100233, Sigma) 몫
 * - Evidence summary에는 username/password를 넣지 않는다
 */
@Component
public class BruteForceValidator implements AttackValidator<BruteForceInput> {

    static final String VALIDATOR_VERSION = "v1";
    // T1110: Brute Force (Caldera 상관정보가 없을 때 기본값)
    static final String DEFAULT_TECHNIQUE_ID = "T1110";

    @Override
    public AttackScenario scenario() {
        return AttackScenario.BRUTE_FORCE;
    }

    @Override
    public AttackObservation validate(ValidationContext<BruteForceInput> ctx) {
        try {
            return observe(ctx);
        } catch (RuntimeException e) {
            return build(ctx, AttackOutcome.UNKNOWN, "UNKNOWN", List.of(),
                    "evaluation failed: " + e.getClass().getSimpleName());
        }
    }

    private AttackObservation observe(ValidationContext<BruteForceInput> ctx) {
        ResultType resultType = ctx.payload().resultType();
        String name = resultType.name();

        return switch (resultType) {
            case AUTH_SUCCESS -> build(ctx, AttackOutcome.SUCCEEDED, name,
                    List.of(new Evidence(EvidenceKind.CREDENTIAL_VALID,
                            "submitted credential accepted and token issued",
                            "brute_force:credential_valid")),
                    "login succeeded for this request (multi-step brute force is judged by detection)");
            case AUTH_FAIL -> build(ctx, AttackOutcome.FAILED, name, List.of(),
                    "invalid credentials");
            case DB_ERROR -> build(ctx, AttackOutcome.UNKNOWN, name, List.of(),
                    "credential check failed with database error");
        };
    }

    private AttackObservation build(ValidationContext<BruteForceInput> ctx, AttackOutcome outcome,
                                    String resultType, List<Evidence> evidence, String reason) {
        return new AttackObservation(
                ctx.rid(),
                scenario(),
                techniqueId(ctx),
                outcome,
                resultType,
                evidence,
                reason,
                ctx.correlation(),
                Instant.now(),
                VALIDATOR_VERSION);
    }

    private static String techniqueId(ValidationContext<BruteForceInput> ctx) {
        if (ctx.correlation() != null && ctx.correlation().getTechniqueId() != null) {
            return ctx.correlation().getTechniqueId();
        }
        return DEFAULT_TECHNIQUE_ID;
    }
}
