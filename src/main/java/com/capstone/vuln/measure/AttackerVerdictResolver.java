package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * Caldera op facts → (paw, abilityId) 별 attacker_verdict (수집기 3, 결정 B).
 *
 * <p>op JSON 의 chain[].facts 에서 trait "{scenario}.verdict" 값을 {@link AttackOutcome} 로 읽는다
 * (ssrf.verdict 등 fact 우선). fact 가 없으면 그 (paw, abilityId) 는 맵에 넣지 않는다 → b-2b/엔진에서
 * attacker_verdict=null → UNKNOWN 유도 (결정 C: differential 억지 산출 안 함).
 * evidence.kind·differential 은 verdict 산출엔 쓰지 않는다(현재 non-blind 직접판정이라 결정2 미사용).
 */
public class AttackerVerdictResolver {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VERDICT_SUFFIX = ".verdict";

    private final OperationFactsSource source;

    public AttackerVerdictResolver(OperationFactsSource source) {
        this.source = source;
    }

    public Map<PawAbility, AttackOutcome> resolve(String opId) {
        JsonNode op;
        try {
            op = MAPPER.readTree(source.fetchOperationJson(opId));
        } catch (Exception e) {
            throw new IllegalStateException("Caldera operation facts 파싱 실패: opId=" + opId, e);
        }

        Map<PawAbility, AttackOutcome> verdicts = new LinkedHashMap<>();
        for (JsonNode link : op.path("chain")) {
            String paw = text(link.path("paw"));
            String abilityId = text(link.path("ability").path("ability_id"));
            if (paw == null || abilityId == null) {
                continue;
            }
            AttackOutcome verdict = null;
            for (JsonNode fact : link.path("facts")) {
                String trait = text(fact.path("trait"));
                if (trait != null && trait.endsWith(VERDICT_SUFFIX)) {
                    verdict = parseOutcome(text(fact.path("value")));
                }
            }
            if (verdict != null) {
                verdicts.put(new PawAbility(paw, abilityId), verdict);
            }
        }
        return verdicts;
    }

    /** fact 값 → AttackOutcome. 알 수 없는/누락 값은 null (UNKNOWN 유도). */
    private static AttackOutcome parseOutcome(String value) {
        if (value == null) {
            return null;
        }
        try {
            return AttackOutcome.valueOf(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
