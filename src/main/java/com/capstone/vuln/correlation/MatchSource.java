package com.capstone.vuln.correlation;

/**
 * 상관분석 결과의 대표 채널 (Correlation Success Rate 집계 단위)
 *
 * 생산 계층의 {@link CorrelationSource}(로그에 기록되는 추출 채널)와 별개다.
 * 소비 계층은 RID 를 추가로 구분하고, 임계치 미만(TIME_ONLY)은 NONE 으로 본다.
 */
public enum MatchSource {
    RID,
    HEADER,
    UA_FALLBACK,
    NONE
}
