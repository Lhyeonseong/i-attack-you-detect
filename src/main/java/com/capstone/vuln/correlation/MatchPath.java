package com.capstone.vuln.correlation;

/**
 * 공격 이벤트와 탐지 알림을 어떤 경로로 연결했는지 (S3 소비 계층)
 * - RID: 요청 ID 직접 일치
 * - HEADER: X-Caldera-* 헤더(opId/ability) 일치
 * - UA_FALLBACK: User-Agent 파싱 결과 일치
 * - TIME_ONLY: 시간창(30초)·IP 근접만 일치 — 판정 근거로 쓰지 않음
 */
public enum MatchPath {
    RID,
    HEADER,
    UA_FALLBACK,
    TIME_ONLY
}
