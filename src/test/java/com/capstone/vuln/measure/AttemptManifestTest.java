package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AttemptRole;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 시도 단위 manifest (ADR-S4-01 v1.1 R6·R10) — 대조군 판별은 정답지 쪽(요청 대상·ability 정의)만 쓴다.
 * manifest 는 코드 상수이므로 실제 Caldera adversary/ability yml 과 어긋나지 않는지 여기서 고정한다.
 */
class AttemptManifestTest {

    private static final AttemptManifest M = AttemptManifest.ATTACK_VALIDATION_WEB;

    private static final String SQLI = "e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c";
    private static final String SSRF = "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
    private static final String PT = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String BF = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";

    @Test
    void per_operation_units_sqli1_pt3_ssrf2plus1control_bf1() {
        assertEquals(1, M.entry(SQLI).attackUnits());
        assertEquals(3, M.entry(PT).attackUnits());
        assertEquals(2, M.entry(SSRF).attackUnits());
        assertEquals(1, M.entry(SSRF).controlUnits());
        assertEquals(1, M.entry(BF).attackUnits()); // R6: BF = 시퀀스 1건
        assertEquals(7, M.attacksPerOperation());
        assertEquals(1, M.controlsPerOperation());
    }

    @Test
    void ssrf_control_target_is_control_and_metadata_is_attack() {
        assertEquals(AttemptRole.CONTROL, M.roleOf(SSRF, "url=http://example.com/"));
        assertEquals(AttemptRole.ATTACK,
                M.roleOf(SSRF, "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role"));
    }

    @Test
    void control_is_defined_per_ability_not_by_target_alone() {
        // 대조군이 없는 ability 는 같은 대상이어도 ATTACK, 미등록 ability·args 없음도 ATTACK
        assertEquals(AttemptRole.ATTACK, M.roleOf(PT, "url=http://example.com/"));
        assertEquals(AttemptRole.ATTACK, M.roleOf("unknown-ability", "url=http://example.com/"));
        assertEquals(AttemptRole.ATTACK, M.roleOf(SSRF, null));
    }

    @Test
    void gt_log_reader_classifies_roles_by_rid() {
        String log = """
                {"time":1000000001000,"rid":"r-md","correlation":{"op_id":"mcukpa","ability_id":"%1$s","source":"HEADER"},"validation":{"outcome":"SUCCEEDED","technique_id":"T1190"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/preview"},"args":"url=http://169.254.169.254/latest/meta-data/"}}
                {"time":1000000002000,"rid":"r-ctl","correlation":{"op_id":"mcukpa","ability_id":"%1$s","source":"HEADER"},"validation":{"outcome":"FAILED","technique_id":"T1190"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/preview"},"args":"url=http://example.com/"}}
                """.formatted(SSRF);
        GtLogReader.GtWindow w = new GtLogReader(() -> log)
                .readWindow(Instant.ofEpochMilli(1_000_000_000_000L), Instant.ofEpochMilli(1_000_000_010_000L));

        assertEquals(2, w.events().size());
        assertEquals(Map.of("r-md", AttemptRole.ATTACK, "r-ctl", AttemptRole.CONTROL), w.roles());
    }

    @Test
    void manifest_matches_caldera_adversary_and_ability_definitions() throws IOException {
        Path root = Path.of(".");
        List<String> ordering = RulesDigest.atomicOrdering(root.resolve(RulesDigest.CALDERA_ADVERSARY));
        assertEquals(new LinkedHashSet<>(ordering), Set.copyOf(M.abilityIds()),
                "manifest ability 집합 = adversary atomic_ordering");

        Map<String, Path> files = RulesDigest.abilityFiles(root.resolve(RulesDigest.CALDERA_ABILITIES_DIR), ordering);
        String ssrf = Files.readString(files.get(SSRF));
        assertTrue(ssrf.contains("CTL=\"" + M.entry(SSRF).controlTarget() + "\""), "SSRF 대조 대상이 ability 정의와 일치");
    }
}
