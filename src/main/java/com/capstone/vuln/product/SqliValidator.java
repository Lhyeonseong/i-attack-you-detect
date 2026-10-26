package com.capstone.vuln.product;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.AttackValidator;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.evaluator.SqliResultType;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * SQLi 공격 성공 판정기
 * - 판정 자체는 기존 SqliEvaluator에 위임하고, SqliResultType -> AttackOutcome 매핑만 담당
 * - Evidence summary에는 쿼리 결과/에러 원문을 넣지 않는다
 */
@Component
public class SqliValidator implements AttackValidator<SqliInput> {

    static final String VALIDATOR_VERSION = "v1";
    // T1190: Exploit Public-Facing Application (Caldera 상관정보가 없을 때 기본값)
    static final String DEFAULT_TECHNIQUE_ID = "T1190";

    private final SqliEvaluator sqliEvaluator;

    public SqliValidator(SqliEvaluator sqliEvaluator) {
        this.sqliEvaluator = sqliEvaluator;
    }

    @Override
    public AttackScenario scenario() {
        return AttackScenario.SQLI;
    }

    @Override
    public AttackObservation validate(ValidationContext<SqliInput> ctx) {
        SqliResultType resultType;
        try {
            SqliInput input = ctx.payload();
            resultType = input.hasError()
                    ? sqliEvaluator.evaluateError(input.errorMessage())
                    : sqliEvaluator.evaluateNormal(input.rows(), input.elapsedMs(), input.contentLength());
        } catch (RuntimeException e) {
            return build(ctx, AttackOutcome.UNKNOWN, SqliResultType.UNKNOWN.name(), List.of(),
                    "evaluation failed: " + e.getClass().getSimpleName());
        }
        return observe(ctx, resultType);
    }

    /**
     * SqliResultType -> AttackOutcome 매핑 (DB 없이 단위 테스트할 수 있도록 분리)
     * - 컨트롤러가 SqliEvaluator로 이미 얻은 결과를 재평가 없이 넘길 때도 사용
     */
    public AttackObservation observe(ValidationContext<SqliInput> ctx, SqliResultType resultType) {
        SqliInput input = ctx.payload();
        String name = resultType.name();

        return switch (resultType) {
            case UNION_DATA_LEAKED -> build(ctx, AttackOutcome.SUCCEEDED, name,
                    List.of(evidence(EvidenceKind.DATA_EXPOSURE, resultType,
                            "credential hash pattern found in query result (rows=" + rowCount(input) + ")")),
                    "UNION query exposed credential hash values");
            case SQL_ERROR_EXPOSED -> build(ctx, AttackOutcome.SUCCEEDED, name,
                    List.of(evidence(EvidenceKind.RESPONSE_PATTERN, resultType,
                            "PostgreSQL error pattern matched in error chain")),
                    "database error details exposed to client");
            case TIME_BASED_DELAY -> build(ctx, AttackOutcome.EXECUTED, name,
                    List.of(evidence(EvidenceKind.TIMING, resultType,
                            "elapsedMs=" + input.elapsedMs() + " exceeded time threshold")),
                    "response delay suggests time-based injection");
            case LENGTH_ANOMALY -> build(ctx, AttackOutcome.EXECUTED, name,
                    List.of(evidence(EvidenceKind.TIMING, resultType,
                            "contentLength=" + input.contentLength() + " exceeded baseline")),
                    "response length anomaly suggests injected query");
            case NORMAL -> build(ctx, AttackOutcome.FAILED, name, List.of(),
                    "no injection effect observed");
            case UNKNOWN -> build(ctx, AttackOutcome.UNKNOWN, name, List.of(),
                    "error did not match SQL error pattern");
        };
    }

    private AttackObservation build(ValidationContext<SqliInput> ctx, AttackOutcome outcome,
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

    private static Evidence evidence(EvidenceKind kind, SqliResultType resultType, String summary) {
        return new Evidence(kind, summary, "sqli:" + resultType.name().toLowerCase());
    }

    private static String techniqueId(ValidationContext<SqliInput> ctx) {
        if (ctx.correlation() != null && ctx.correlation().getTechniqueId() != null) {
            return ctx.correlation().getTechniqueId();
        }
        return DEFAULT_TECHNIQUE_ID;
    }

    private static int rowCount(SqliInput input) {
        return input.rows() == null ? 0 : input.rows().size();
    }
}
