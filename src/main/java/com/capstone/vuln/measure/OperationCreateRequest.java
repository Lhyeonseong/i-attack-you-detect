package com.capstone.vuln.measure;

/**
 * Caldera operation 생성 요청 값(측정 도구 전용). 고정 필드(state/auto_close/autonomous/obfuscator/
 * jitter/visibility)는 HTTP 클라이언트가 채운다 — 여기엔 측정이 제어하는 값만 담는다.
 */
public record OperationCreateRequest(
        String name,
        String adversaryId,
        String plannerId,
        String sourceId,
        String group) {
}
