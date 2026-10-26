package com.capstone.vuln.correlation;

import java.time.Instant;

/**
 * 앱 OCSF 로그(attack.json.log) 1건을 엔진 입력용으로 정규화한 것
 * - key: correlation.op_id / correlation.ability_id / rid
 * - attackTime: time (epoch ms)
 * - srcIp: src_endpoint.ip, endpoint: http_request.url.path
 * - username: 로그인 시도 계정 (http_request.args 의 username, 없으면 null) — BF 그룹 하위 키
 * - gtOutcome: validation.outcome (정답지 — 채점에만 사용)
 */
public record AttackEvent(CorrelationKey key, String scenario, String techniqueId, Instant attackTime,
                          String srcIp, String endpoint, String username, GroundTruthOutcome gtOutcome) {

    public AttackEvent withKey(CorrelationKey newKey) {
        return new AttackEvent(newKey, scenario, techniqueId, attackTime, srcIp, endpoint, username, gtOutcome);
    }
}
