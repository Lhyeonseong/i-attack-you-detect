package com.capstone.vuln.correlation;

import com.capstone.vuln.attack.AttackOutcome;

/**
 * 정규화된 공격 결과 3값. 서버 측 정답지(Ground Truth)와 공격자 측 판정을 같은 축으로 비교하는 데 쓴다.
 * 정답지는 채점(Verdict 결정표)에만 쓰고 탐지 상태 계산에는 쓰지 않는다 (B안).
 * EXECUTED(지연/길이 이상 등 간접 신호)는 UNKNOWN — 간접 신호 단독은 성공이 아니다 (결정2).
 */
public enum GroundTruthOutcome {
    SUCCEEDED,
    FAILED,
    UNKNOWN;

    /** 로그 validation.outcome 문자열 → SUCCEEDED/FAILED 외(EXECUTED·UNKNOWN·null·기타)는 전부 UNKNOWN */
    public static GroundTruthOutcome fromValidation(String outcome) {
        if ("SUCCEEDED".equals(outcome)) return SUCCEEDED;
        if ("FAILED".equals(outcome)) return FAILED;
        return UNKNOWN;
    }

    /** 공격자 측 판정(Caldera fact) 정규화. fact 누락(null)은 null 그대로 */
    public static GroundTruthOutcome fromAttackOutcome(AttackOutcome outcome) {
        return outcome == null ? null : fromValidation(outcome.name());
    }
}
