package com.capstone.vuln.attack;

import com.capstone.vuln.correlation.CorrelationInfo;

import java.time.Instant;

/**
 * Validator 입력 공통 틀
 * - payload(C)는 공격별 입력 (예: SQLi는 쿼리 결과/에러/elapsed/length 묶음)
 */
public record ValidationContext<C>(
        String rid,
        CorrelationInfo correlation,
        Instant startedAt,
        int statusCode,
        C payload) {
}
