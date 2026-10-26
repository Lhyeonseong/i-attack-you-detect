package com.capstone.vuln.measure;

/**
 * runOnce 반환값. state 는 Caldera operation 최종 state 또는 타임아웃 시 "timeout".
 * 귀속은 opId(operation UUID)로 한다.
 */
public record RunResult(String opId, String state, long durationMs) {
}
