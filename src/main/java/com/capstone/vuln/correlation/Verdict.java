package com.capstone.vuln.correlation;

/**
 * 공격 1건에 대한 최종 판정 (7상태). 산출 규칙은 Verdict Engine 슬라이스에서 정한다.
 */
public enum Verdict {
    /** 공격 성공 + 못 잡음. 가장 중요한 빈틈 */
    SUCCEEDED_MISSED,
    SUCCEEDED_DETECTED,
    /** 공격 성공 + 차단됨 (확장 설계) */
    SUCCEEDED_BLOCKED,
    /** 차단됨 (확장 설계) */
    BLOCKED,
    FAILED_DETECTED,
    /** 공격 실패 + 못 봄. 가시성 빈틈이며 Miss Rate 에는 넣지 않는다 */
    FAILED_UNSEEN,
    /** 확실하지 않음. 모든 비율 계산에서 빠진다 */
    UNCERTAIN
}
