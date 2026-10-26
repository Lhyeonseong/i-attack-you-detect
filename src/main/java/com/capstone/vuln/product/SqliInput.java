package com.capstone.vuln.product;

import java.util.List;
import java.util.Map;

/**
 * SqliValidator 입력 (ValidationContext.payload)
 * - 쿼리 성공 시: rows/elapsedMs/contentLength 사용, errorMessage는 null
 * - 쿼리 실패 시: errorMessage(cause 체인 포함 전체 메시지) 사용
 */
public record SqliInput(
        List<Map<String, Object>> rows,
        String errorMessage,
        long elapsedMs,
        long contentLength) {

    public static SqliInput ofRows(List<Map<String, Object>> rows, long elapsedMs, long contentLength) {
        return new SqliInput(rows, null, elapsedMs, contentLength);
    }

    public static SqliInput ofError(String errorMessage, long elapsedMs) {
        return new SqliInput(List.of(), errorMessage, elapsedMs, 0);
    }

    public boolean hasError() {
        return errorMessage != null;
    }
}
