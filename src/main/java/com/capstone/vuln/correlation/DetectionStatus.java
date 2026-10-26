package com.capstone.vuln.correlation;

public enum DetectionStatus {
    DETECTED,
    NOT_DETECTED,
    /** 차단 모드 도입 시 사용 (현재 IDS 전용, 확장 설계) */
    BLOCKED
}
