package com.capstone.vuln.evaluator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * SQLi 응답 판별 전용
 * - 컨트롤러와 분리하여 result_type 세분화 책임을 가짐
 * - application.yml의 sqli.* 임계값으로 판별 기준 조정
 * - 로직 변경이 필요한 경우에만 이 클래스를 수정
 */
@Component
public class SqliEvaluator {

    // PostgreSQL 원본 + Spring 감싼 메시지까지 포괄
    private static final Pattern PG_ERROR = Pattern.compile(
            "(ERROR: syntax error" +
            "|syntax error at or near" +
            "|unterminated quoted string" +
            "|pg_" +
            "|relation .* does not exist" +
            "|column .* does not exist" +
            "|operator does not exist" +
            "|UNION types .* cannot be matched" +
            "|bad SQL grammar" +
            "|BadSqlGrammar" +
            "|PSQLException)",
            Pattern.CASE_INSENSITIVE);

    // UNION 공격으로 users.password가 유출될 때 bcrypt/argon2/scrypt 해시 패턴 검출
    private static final Pattern HASH_PATTERN =
            Pattern.compile("\\$2[aby]\\$\\d{2}\\$|\\$argon2|\\$scrypt");

    @Value("${sqli.baseline-length}")
    private long baselineLength;

    @Value("${sqli.content-length-multiplier}")
    private double lengthMultiplier;

    @Value("${sqli.time-threshold-ms}")
    private long timeThresholdMs;

    public SqliResultType evaluateNormal(List<Map<String, Object>> rows,
                                         long elapsedMs,
                                         long contentLength) {
                                            
        // 1순위: UNION 데이터 유출 판정
        // UNION SELECT 결과는 컬럼명이 products 기준으로 유지될 수 있으므로,
        // 컬럼명보다 값 내부의 해시 패턴을 우선 확인한다.
        for (Map<String, Object> row : rows) {
            for (Object value : row.values()) {
                if (value == null) continue;

                if (HASH_PATTERN.matcher(value.toString()).find()) {
                    return SqliResultType.UNION_DATA_LEAKED;
                }
            }
        }

        // 2순위: Time-based SQLi 판정
        if (elapsedMs >= timeThresholdMs) {
            return SqliResultType.TIME_BASED_DELAY;
        }

        // 3순위: 응답 길이 이상 판정
        if (contentLength > baselineLength * lengthMultiplier) {
            return SqliResultType.LENGTH_ANOMALY;
        }

        return SqliResultType.NORMAL;
    }

    public SqliResultType evaluateError(String errorMessage) {
        if (errorMessage != null && PG_ERROR.matcher(errorMessage).find()) {
            return SqliResultType.SQL_ERROR_EXPOSED;
        }

        return SqliResultType.UNKNOWN;
    }
}