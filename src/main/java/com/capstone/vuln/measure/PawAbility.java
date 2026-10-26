package com.capstone.vuln.measure;

/**
 * attacker_verdict 맵의 키 (결정 B). facts 에는 rid 가 없고 paw+ability_id 만 있으며,
 * BF 는 13 rid 를 1 verdict 로 묶어 대표 rid 가 상관(correlate) 이후 결정되므로, 수집 단계에서는
 * correlation_key(rid) 가 아니라 (paw, abilityId) 로 키를 둔다. b-2b 가 Correlation.key 의
 * agentPaw()+abilityId() 로 매칭해 setAttackerVerdict 한다.
 */
public record PawAbility(String paw, String abilityId) {
}
