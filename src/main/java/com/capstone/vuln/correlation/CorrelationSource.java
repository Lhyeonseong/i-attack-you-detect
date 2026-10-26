package com.capstone.vuln.correlation;

/**
 * Correlation 정보가 어떤 채널에서 추출되었는지 표시
 * - HEADER: Primary 채널 (X-Caldera-* 헤더)
 * - UA_FALLBACK: Secondary 채널 (User-Agent 정규식 파싱)
 * - NONE: 둘 다 추출 실패 (UNKNOWN 처리 대상)
 */
public enum CorrelationSource {
    HEADER,
    UA_FALLBACK,
    NONE
}