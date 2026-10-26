package com.capstone.vuln.ssrf;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.AttackValidator;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * SSRF 공격 성공 판정기 (ground-truth)
 * - PreviewController의 fetch 결과(result_type)만 관찰한다. 취약 로직(아웃바운드 요청 자체)에는 관여하지 않는다.
 * - KISA SF(성공/실패) 판단기준:
 *     도달 + 내부자원(메타데이터/내부 대역)  -> SUCCEEDED (METADATA_REACHED evidence)
 *     화이트리스트/가드 차단               -> FAILED
 *     연결오류·모호(외부 공개자원 fetch 포함) -> UNKNOWN / FAILED
 * - Evidence summary 에는 응답 본문/자격증명 원문을 넣지 않는다 (sentinel 도달 여부/host-class 만)
 */
@Component
public class SsrfValidator implements AttackValidator<SsrfInput> {

    static final String VALIDATOR_VERSION = "v1";
    // T1190: Exploit Public-Facing Application (Caldera 상관정보가 없을 때 기본값)
    static final String DEFAULT_TECHNIQUE_ID = "T1190";

    @Override
    public AttackScenario scenario() {
        return AttackScenario.SSRF;
    }

    @Override
    public AttackObservation validate(ValidationContext<SsrfInput> ctx) {
        try {
            return observe(ctx);
        } catch (RuntimeException e) {
            return build(ctx, AttackOutcome.UNKNOWN, "UNKNOWN", List.of(),
                    "evaluation failed: " + e.getClass().getSimpleName());
        }
    }

    private AttackObservation observe(ValidationContext<SsrfInput> ctx) {
        SsrfInput input = ctx.payload();
        String name = input.resultType().name();

        return switch (input.resultType()) {
            case FETCHED -> (input.internalTarget() || input.sentinelReached())
                    ? build(ctx, AttackOutcome.SUCCEEDED, name,
                            List.of(new Evidence(EvidenceKind.METADATA_REACHED,
                                    "internal resource reached (host-class=internal, sentinel="
                                            + input.sentinelReached() + ", code=" + input.responseCode() + ")",
                                    "ssrf:metadata_reached")),
                            "server-side request reached internal-only resource")
                    : build(ctx, AttackOutcome.FAILED, name, List.of(),
                            "external/public resource fetched (no SSRF effect)");
            case BLOCKED -> build(ctx, AttackOutcome.FAILED, name, List.of(),
                    "outbound request blocked by whitelist/scheme guard");
            case ERROR -> build(ctx, AttackOutcome.UNKNOWN, name, List.of(),
                    "connection error/timeout — outcome ambiguous");
        };
    }

    private AttackObservation build(ValidationContext<SsrfInput> ctx, AttackOutcome outcome,
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

    private static String techniqueId(ValidationContext<SsrfInput> ctx) {
        if (ctx.correlation() != null && ctx.correlation().getTechniqueId() != null) {
            return ctx.correlation().getTechniqueId();
        }
        return DEFAULT_TECHNIQUE_ID;
    }
}
