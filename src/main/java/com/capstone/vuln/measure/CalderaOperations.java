package com.capstone.vuln.measure;

/**
 * Caldera operation 생성·조회 추상화(측정 도구 전용). 실패(HTTP 4xx/5xx)는 예외로 던진다.
 * 테스트는 이 인터페이스를 가짜 구현으로 대체해 폴링/타임아웃 로직만 검증한다.
 */
public interface CalderaOperations {

    /** operation 1개를 생성(state=running 으로 즉시 시작)하고 그 UUID 를 반환. */
    String create(OperationCreateRequest request);

    /** operation 현재 state 를 1회 조회(단일 진실원 — chain 추론 안 함). */
    String poll(String opId);
}
