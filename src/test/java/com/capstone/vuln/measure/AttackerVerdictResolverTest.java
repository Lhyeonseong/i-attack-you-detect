package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackerVerdictResolverTest {

    // link1 ssrf.verdict=SUCCEEDED, link2 facts 없음(verdict 없음), link3 bf.verdict=FAILED
    private static final String OP = """
            {"id":"op-uuid","chain":[
              {"paw":"mcukpa","ability":{"ability_id":"abil-ssrf"},
               "facts":[{"trait":"ssrf.verdict","value":"SUCCEEDED"},{"trait":"ssrf.evidence.kind","value":"METADATA_REACHED"}]},
              {"paw":"mcukpa","ability":{"ability_id":"abil-noverdict"},"facts":[]},
              {"paw":"mcukpa","ability":{"ability_id":"7aa89a87"},
               "facts":[{"trait":"bf.verdict","value":"FAILED"},{"trait":"bf.evidence.kind","value":"none"}]}
            ]}""";

    private Map<PawAbility, AttackOutcome> resolve() {
        return new AttackerVerdictResolver(opId -> OP).resolve("op-uuid");
    }

    @Test
    void keys_by_paw_and_ability_with_verdict_value() {
        Map<PawAbility, AttackOutcome> verdicts = resolve();
        assertEquals(AttackOutcome.SUCCEEDED, verdicts.get(new PawAbility("mcukpa", "abil-ssrf")));
        assertEquals(AttackOutcome.FAILED, verdicts.get(new PawAbility("mcukpa", "7aa89a87")));
    }

    @Test
    void link_without_verdict_fact_is_absent_not_null_entry() {
        Map<PawAbility, AttackOutcome> verdicts = resolve();
        assertFalse(verdicts.containsKey(new PawAbility("mcukpa", "abil-noverdict")),
                "verdict fact 없으면 맵에 넣지 않는다(→ UNKNOWN 유도)");
        assertEquals(2, verdicts.size());
    }

    @Test
    void unknown_fact_value_yields_absent() {
        String op = "{\"chain\":[{\"paw\":\"p\",\"ability\":{\"ability_id\":\"a\"},"
                + "\"facts\":[{\"trait\":\"x.verdict\",\"value\":\"WeirdValue\"}]}]}";
        Map<PawAbility, AttackOutcome> verdicts = new AttackerVerdictResolver(id -> op).resolve("x");
        assertTrue(verdicts.isEmpty());
    }
}
