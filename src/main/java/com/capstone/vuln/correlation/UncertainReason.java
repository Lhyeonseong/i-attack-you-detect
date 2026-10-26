package com.capstone.vuln.correlation;

/** UNCERTAIN 판정 사유 (UNCERTAIN 이 아니면 null) */
public enum UncertainReason {
    /** 정답지가 UNKNOWN (EXECUTED 등 간접 신호 포함) */
    GT_UNKNOWN,
    /** 링크된 alert 는 있으나 최고 confidence < 0.7 */
    LOW_CONFIDENCE,
    /** 정답지 UNKNOWN 이고 공격자 측 fact 도 없음 */
    NO_EVIDENCE
}
