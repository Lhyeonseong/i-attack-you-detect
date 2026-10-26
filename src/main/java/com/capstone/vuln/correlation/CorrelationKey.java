package com.capstone.vuln.correlation;

/**
 * 공격 1건 식별 키
 * - opId: Caldera operation UUID (해석 실패 시 paw 그대로 — opIdResolved=false). 라벨·집계용
 * - agentPaw: 로그 원본 correlation.op_id (= Caldera agent paw). alert 매칭은 이 값으로 한다
 * - abilityId / rid: 로그 원본 그대로
 */
public record CorrelationKey(String opId, String agentPaw, String abilityId, String rid, boolean opIdResolved) {

    /** 로그 원본 키: correlation.op_id 는 paw 이므로 opId=agentPaw=paw, 미해석 상태 */
    public CorrelationKey(String paw, String abilityId, String rid) {
        this(paw, paw, abilityId, rid, false);
    }

    public CorrelationKey resolvedTo(String operationUuid) {
        return new CorrelationKey(operationUuid, agentPaw, abilityId, rid, true);
    }
}
