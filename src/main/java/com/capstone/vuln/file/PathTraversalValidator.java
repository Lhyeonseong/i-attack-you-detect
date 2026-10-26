package com.capstone.vuln.file;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.AttackValidator;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.file.PathTraversalInput.ResultType;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Path Traversal 공격 성공 판정기
 * - FileController의 기존 result_type -> AttackOutcome 매핑만 담당 (경로 검증 누락 로직에는 관여하지 않음)
 * - FILE_RETURNED라도 업로드 디렉터리 안의 파일이면 정상 다운로드이므로 FAILED
 * - Evidence summary에는 파일 내용/경로 원문을 넣지 않는다
 */
@Component
public class PathTraversalValidator implements AttackValidator<PathTraversalInput> {

    static final String VALIDATOR_VERSION = "v1";
    // T1190: Exploit Public-Facing Application (Caldera 상관정보가 없을 때 기본값)
    static final String DEFAULT_TECHNIQUE_ID = "T1190";

    @Override
    public AttackScenario scenario() {
        return AttackScenario.PATH_TRAVERSAL;
    }

    @Override
    public AttackObservation validate(ValidationContext<PathTraversalInput> ctx) {
        try {
            return observe(ctx);
        } catch (RuntimeException e) {
            return build(ctx, AttackOutcome.UNKNOWN, "UNKNOWN", List.of(),
                    "evaluation failed: " + e.getClass().getSimpleName());
        }
    }

    private AttackObservation observe(ValidationContext<PathTraversalInput> ctx) {
        PathTraversalInput input = ctx.payload();
        ResultType resultType = input.resultType();
        String name = resultType.name();

        return switch (resultType) {
            case FILE_RETURNED -> outsideBaseDir(input)
                    ? build(ctx, AttackOutcome.SUCCEEDED, name,
                            List.of(new Evidence(EvidenceKind.FILE_DISCLOSED,
                                    "file outside upload dir returned (type=" + input.contentType()
                                            + " size=" + input.contentLength() + ")",
                                    "path_traversal:file_disclosed")),
                            "file outside upload dir disclosed via download endpoint")
                    : build(ctx, AttackOutcome.FAILED, name, List.of(),
                            "file within upload dir returned (no traversal effect)");
            case NOT_FOUND -> build(ctx, AttackOutcome.FAILED, name, List.of(),
                    "target file not found");
            case ERROR -> build(ctx, AttackOutcome.FAILED, name, List.of(),
                    "file read failed (e.g. permission denied)");
        };
    }

    // 정규화(.. 해소) 후 업로드 디렉터리 밖이면 traversal 성공으로 본다
    private static boolean outsideBaseDir(PathTraversalInput input) {
        Path base = input.baseDir().toAbsolutePath().normalize();
        Path target = input.requestedPath().toAbsolutePath().normalize();
        return !target.startsWith(base);
    }

    private AttackObservation build(ValidationContext<PathTraversalInput> ctx, AttackOutcome outcome,
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

    private static String techniqueId(ValidationContext<PathTraversalInput> ctx) {
        if (ctx.correlation() != null && ctx.correlation().getTechniqueId() != null) {
            return ctx.correlation().getTechniqueId();
        }
        return DEFAULT_TECHNIQUE_ID;
    }
}
