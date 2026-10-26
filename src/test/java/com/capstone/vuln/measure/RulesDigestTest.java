package com.capstone.vuln.measure;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** T4 — RulesDigest: 결정적, ability 파일 1바이트 변경 → 다른 해시 */
class RulesDigestTest {

    private static final String AB1 = "11111111-1111-1111-1111-111111111111";
    private static final String AB2 = "22222222-2222-2222-2222-222222222222";

    @TempDir
    Path root;

    private void fixture() throws IOException {
        write(RulesDigest.WAZUH_RULES, "<group name=\"vuln-webapp\"/>\n");
        write(RulesDigest.SURICATA_RULES, "alert http any any -> any any (sid:1;)\n");
        write(RulesDigest.CALDERA_ADVERSARY, """
                id: adv-1
                atomic_ordering:
                - %s
                - %s
                objective: obj-1
                """.formatted(AB1, AB2));
        write(RulesDigest.CALDERA_ABILITIES_DIR.resolve("a/one.yml"), "- id: " + AB1 + "\n  name: one\n");
        write(RulesDigest.CALDERA_ABILITIES_DIR.resolve("b/two.yml"), "- id: " + AB2 + "\n  name: two\n");
        write(RulesDigest.CALDERA_ABILITIES_DIR.resolve("b/other.yml"), "- id: 33333333-0000-0000-0000-000000000000\n");
    }

    private void write(Path rel, String content) throws IOException {
        Path p = root.resolve(rel);
        Files.createDirectories(p.getParent());
        Files.writeString(p, content);
    }

    @Test
    void same_input_gives_same_digest() throws IOException {
        fixture();
        assertEquals(RulesDigest.compute(root).toJson(), RulesDigest.compute(root).toJson());
    }

    @Test
    void one_byte_change_in_ability_file_changes_digest() throws IOException {
        fixture();
        RulesDigest before = RulesDigest.compute(root);
        write(RulesDigest.CALDERA_ABILITIES_DIR.resolve("b/two.yml"), "- id: " + AB2 + "\n  name: twO\n");
        RulesDigest after = RulesDigest.compute(root);

        assertNotEquals(before.toJson(), after.toJson());
        assertEquals(before.wazuhRules(), after.wazuhRules());
        assertEquals(before.calderaAbilities().get(AB1), after.calderaAbilities().get(AB1));
        assertNotEquals(before.calderaAbilities().get(AB2), after.calderaAbilities().get(AB2));
    }

    @Test
    void json_has_four_keys_and_only_referenced_abilities() throws IOException {
        fixture();
        JsonNode json = new ObjectMapper().readTree(RulesDigest.compute(root).toJson());
        assertEquals(4, json.size());
        assertTrue(json.path("wazuh_rules").asText().matches("[0-9a-f]{64}"));
        assertTrue(json.path("suricata_rules").asText().matches("[0-9a-f]{64}"));
        assertTrue(json.path("caldera_adversary").asText().matches("[0-9a-f]{64}"));
        assertEquals(2, json.path("caldera_abilities").size()); // other.yml 은 adversary 미참조 → 제외
    }

    @Test
    void missing_ability_file_fails() throws IOException {
        fixture();
        Files.delete(root.resolve(RulesDigest.CALDERA_ABILITIES_DIR.resolve("a/one.yml")));
        assertThrows(IllegalStateException.class, () -> RulesDigest.compute(root));
    }

    @Test
    void real_repository_resolves_four_abilities() {
        RulesDigest digest = RulesDigest.compute(Path.of("."));
        assertEquals(4, digest.calderaAbilities().size());
    }
}
