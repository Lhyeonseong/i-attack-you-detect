package com.capstone.vuln.controller;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.auth.BruteForceInput;
import com.capstone.vuln.auth.BruteForceValidator;
import com.capstone.vuln.correlation.*;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.logging.HttpExchange;
import com.capstone.vuln.util.JwtUtil;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private CalderaCorrelationExtractor extractor;
    @Autowired private AttackLogger attackLogger;
    @Autowired private BruteForceValidator bruteForceValidator;
    @Autowired private JsonMapper objectMapper;

    private static final String LOGIN_PATH = "/api/auth/login";

    /**
     * [VULNERABLE] Brute Force 전용
     *  의도적으로 PreparedStatement를 사용하여 SQLi 우회를 차단
     *    → BF 시나리오와 SQLi 시나리오의 분류 충돌을 원천 제거
     *  취약점은 rate limit / lockout / captcha 미적용에 한정
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String requestId = UUID.randomUUID().toString();
        Instant requestTime = Instant.now();
        long start = System.currentTimeMillis();
        String username = body.get("username");
        String password = body.get("password");
        // JSON 로그 args에는 username만 기록한다 (비밀번호 금지)
        String args = "username=" + username;

        CorrelationInfo correlation = extractor.extract(request);
        attackLogger.logRequest(requestId, LOGIN_PATH, "POST",
                correlation, username, "login_attempt");

        //  PreparedStatement 사용 — SQLi 차단
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
        List<Map<String, Object>> result;
        try {
            result = jdbcTemplate.queryForList(sql, username, password);
        } catch (Exception e) {
            attackLogger.logResponse(requestId, LOGIN_PATH, correlation, 500,
                    "DB_ERROR", "msg=" + e.getMessage());
            Map<String, Object> errorBody = Map.of("error", "internal");
            logHttpActivity(requestId, requestTime, start, correlation, args, 500, errorBody,
                    BruteForceInput.ResultType.DB_ERROR);
            return ResponseEntity.status(500).body(errorBody);
        }

        if (result.isEmpty()) {
            attackLogger.logResponse(requestId, LOGIN_PATH, correlation, 401,
                    "AUTH_FAIL", "invalid_credentials");
            Map<String, Object> failBody = Map.of(
                    "status", "fail", "message", "Invalid credentials");
            logHttpActivity(requestId, requestTime, start, correlation, args, 401, failBody,
                    BruteForceInput.ResultType.AUTH_FAIL);
            return ResponseEntity.status(401).body(failBody);
        }

        String role = (String) result.get(0).get("role");
        String token = jwtUtil.generateToken(username, role);

        attackLogger.logResponse(requestId, LOGIN_PATH, correlation, 200,
                "AUTH_SUCCESS", "token_issued user=" + username);
        Map<String, Object> successBody = Map.of(
                "status", "success",
                "accessToken", token,
                "tokenType", "Bearer",
                "username", username,
                "role", role);
        logHttpActivity(requestId, requestTime, start, correlation, args, 200, successBody,
                BruteForceInput.ResultType.AUTH_SUCCESS);
        return ResponseEntity.ok(successBody);
    }

    /**
     * OCSF HTTP Activity JSON 로그 (기존 pipe 로그와 병행)
     * - Validator 결과는 validation 에만 기록되고 응답 본문/상태코드에는 영향을 주지 않는다
     */
    private void logHttpActivity(String requestId, Instant requestTime, long start, CorrelationInfo correlation,
                                 String args, int statusCode, Object responseBody,
                                 BruteForceInput.ResultType resultType) {
        long latencyMs = System.currentTimeMillis() - start;
        AttackObservation observation = bruteForceValidator.validate(new ValidationContext<>(
                requestId, correlation, requestTime, statusCode, new BruteForceInput(resultType)));
        HttpExchange exchange = new HttpExchange(requestTime, "POST", LOGIN_PATH,
                correlation.getUserAgent(), args, statusCode, latencyMs, bodyLength(responseBody));
        attackLogger.logHttpActivity(requestId, exchange, correlation, observation);
    }

    // 실제 응답과 같은 Spring JsonMapper로 직렬화한 바이트 수 (실패 시 -1)
    private long bodyLength(Object body) {
        try {
            return objectMapper.writeValueAsBytes(body).length;
        } catch (JacksonException e) {
            return -1;
        }
    }

    /**
     * 보호 자원 — BF 성공 후 토큰 검증용
     */
    @GetMapping("/profile")
    public ResponseEntity<?> profile(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            HttpServletRequest request) {

        String requestId = UUID.randomUUID().toString();
        CorrelationInfo correlation = extractor.extract(request);
        attackLogger.logRequest(requestId, "/api/auth/profile", "GET",
                correlation, null, "has_auth=" + (authHeader != null));

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            attackLogger.logResponse(requestId, "/api/auth/profile", correlation, 401,
                    "NO_TOKEN", "");
            return ResponseEntity.status(401).body(Map.of("error", "No token"));
        }

        try {
            String username = jwtUtil.validateAndGetUsername(authHeader.substring(7));
            attackLogger.logResponse(requestId, "/api/auth/profile", correlation, 200,
                    "ACCESS_GRANTED", "user=" + username);
            return ResponseEntity.ok(Map.of(
                    "username", username, "data", "protected resource accessed"));
        } catch (Exception e) {
            attackLogger.logResponse(requestId, "/api/auth/profile", correlation, 401,
                    "INVALID_TOKEN", "");
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }
    }
}