package com.capstone.vuln.file;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.attack.AttackScenario;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.attack.Evidence.EvidenceKind;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.file.PathTraversalInput.ResultType;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PathTraversalValidatorTest {

    // FileController와 같은 방식(uploadDir + "/" + filename)으로 경로를 만든다
    private static final String UPLOAD_DIR = "app/uploads";
    private static final Path BASE = Paths.get(UPLOAD_DIR);

    private final PathTraversalValidator validator = new PathTraversalValidator();

    private static Path requested(String filename) {
        return Paths.get(UPLOAD_DIR + "/" + filename);
    }

    private static ValidationContext<PathTraversalInput> ctx(PathTraversalInput input) {
        return new ValidationContext<>("rid-1", null, Instant.now(), 200, input);
    }

    @Test
    void fileOutsideUploadDirMapsToSucceededWithFileDisclosed() {
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.fileReturned(
                requested("../../../../etc/passwd"), BASE, 1500, "text")));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
        Evidence evidence = singleEvidence(obs);
        assertEquals(EvidenceKind.FILE_DISCLOSED, evidence.kind());
        // summary에 요청 경로 원문이 들어가면 안 된다
        assertFalse(evidence.summary().contains("passwd"));
        assertCommonFields(obs, ResultType.FILE_RETURNED);
    }

    @Test
    void fileInsideUploadDirMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.fileReturned(
                requested("report.pdf"), BASE, 100, "binary")));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.FILE_RETURNED);
    }

    @Test
    void traversalThatResolvesBackInsideUploadDirMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.fileReturned(
                requested("sub/../report.pdf"), BASE, 100, "binary")));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
    }

    @Test
    void siblingDirectoryWithSamePrefixIsOutside() {
        // app/uploads-backup 은 문자열 prefix는 같지만 app/uploads 밖이다
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.fileReturned(
                requested("../uploads-backup/secret.txt"), BASE, 10, "text")));

        assertEquals(AttackOutcome.SUCCEEDED, obs.outcome());
    }

    @Test
    void notFoundMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.notFound(
                requested("../../../../etc/nope"), BASE)));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.NOT_FOUND);
    }

    @Test
    void errorMapsToFailed() {
        AttackObservation obs = validator.validate(ctx(PathTraversalInput.error(BASE)));

        assertEquals(AttackOutcome.FAILED, obs.outcome());
        assertTrue(obs.evidence().isEmpty());
        assertCommonFields(obs, ResultType.ERROR);
    }

    @Test
    void validateReturnsUnknownWhenEvaluationThrows() {
        AttackObservation obs = validator.validate(ctx(new PathTraversalInput(
                ResultType.FILE_RETURNED, null, BASE, 10, "text")));

        assertEquals(AttackOutcome.UNKNOWN, obs.outcome());
        assertEquals("UNKNOWN", obs.resultType());
    }

    @Test
    void techniqueIdComesFromCorrelationWhenPresent() {
        CorrelationInfo correlation = new CorrelationInfo("op-1", "T1083", "ab-1",
                CorrelationSource.HEADER, "10.0.0.1", "ua");
        ValidationContext<PathTraversalInput> ctx = new ValidationContext<>(
                "rid-2", correlation, Instant.now(), 404, PathTraversalInput.notFound(requested("x"), BASE));

        AttackObservation obs = validator.validate(ctx);

        assertEquals("T1083", obs.techniqueId());
        assertEquals(correlation, obs.correlation());
    }

    private static Evidence singleEvidence(AttackObservation obs) {
        assertEquals(1, obs.evidence().size());
        return obs.evidence().get(0);
    }

    private static void assertCommonFields(AttackObservation obs, ResultType resultType) {
        assertEquals("rid-1", obs.rid());
        assertEquals(AttackScenario.PATH_TRAVERSAL, obs.scenario());
        assertEquals(PathTraversalValidator.DEFAULT_TECHNIQUE_ID, obs.techniqueId());
        assertEquals(resultType.name(), obs.resultType());
        assertEquals("v1", obs.validatorVersion());
    }
}
