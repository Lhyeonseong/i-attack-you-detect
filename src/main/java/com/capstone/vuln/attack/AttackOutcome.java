package com.capstone.vuln.attack;

/**
 * 공격 성공 판정 결과 (공격 종류와 무관한 공통 분류)
 */
public enum AttackOutcome {
    /** 실제 영향 발생 + Evidence 있음 */
    SUCCEEDED,
    /** 공격은 도달했으나 영향 없음 */
    FAILED,
    /** 지연/길이 이상 등 간접 신호만 있어 성공/실패 단정 불가 */
    EXECUTED,
    /** 판정 불가 (예외 등) */
    UNKNOWN
}
