package com.capstone.vuln.logging;

import java.time.Instant;

/**
 * OCSF HTTP Activity 로그의 http_request / http_response 원본값
 * - 요청/응답에서 관찰된 값만 담는다. 판정 결과(outcome, evidence 등)는 넣지 않는다
 */
public record HttpExchange(
        Instant time,
        String method,
        String path,
        String userAgent,
        String args,
        int statusCode,
        long latencyMs,
        long bodyLength) {
}
