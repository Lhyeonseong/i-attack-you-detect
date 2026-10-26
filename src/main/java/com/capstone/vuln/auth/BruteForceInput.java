package com.capstone.vuln.auth;

/**
 * BruteForceValidator 입력 (ValidationContext.payload)
 * - resultType: AuthController가 산출한 기존 result_type (AUTH_SUCCESS / AUTH_FAIL / DB_ERROR)
 * - 비밀번호 등 자격증명 원문은 담지 않는다
 */
public record BruteForceInput(ResultType resultType) {

    public enum ResultType {
        AUTH_SUCCESS,
        AUTH_FAIL,
        DB_ERROR
    }
}
