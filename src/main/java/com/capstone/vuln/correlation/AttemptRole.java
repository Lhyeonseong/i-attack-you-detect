package com.capstone.vuln.correlation;

/**
 * verdict_result.attempt_role (ADR-S4-01 v1.1 R6)
 * - ATTACK: 공격 시도
 * - CONTROL: 공격 ability 안의 대조 요청(예: SSRF 차등 비교용 정상 URL) — 공격 지표 분모에서 제외, 별도 보고
 */
public enum AttemptRole {
    ATTACK,
    CONTROL
}
