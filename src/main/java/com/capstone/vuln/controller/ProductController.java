package com.capstone.vuln.controller;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.*;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.evaluator.SqliResultType;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.logging.HttpExchange;
import com.capstone.vuln.product.SqliInput;
import com.capstone.vuln.product.SqliValidator;
import com.capstone.vuln.repository.VulnRepository;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private static final String SEARCH_PATH = "/api/products/search";

    @Autowired private VulnRepository vulnRepository;
    @Autowired private CalderaCorrelationExtractor extractor;
    @Autowired private AttackLogger attackLogger;
    @Autowired private SqliEvaluator sqliEvaluator;
    @Autowired private SqliValidator sqliValidator;
    @Autowired private JsonMapper objectMapper;

    /**
     * [VULNERABLE] SQL Injection - 의도적 문자열 결합
     */
    @GetMapping("/search")
public Object search(@RequestParam String keyword, HttpServletRequest request) {
    String requestId = UUID.randomUUID().toString();
    Instant requestTime = Instant.now();
    CorrelationInfo correlation = extractor.extract(request);
    String args = "keyword=" + keyword;
    attackLogger.logRequest(requestId, SEARCH_PATH, "GET", correlation, null, args);

    int statusCode = 200;
    long start = System.currentTimeMillis();
    Object body;
    SqliInput input;
    SqliResultType resultType;
    try {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
        List<Map<String, Object>> results = vulnRepository.executeRawQuery(sql);
        long elapsed = System.currentTimeMillis() - start;
        long contentLength = results.toString().length();

        resultType = sqliEvaluator.evaluateNormal(results, elapsed, contentLength);
        input = SqliInput.ofRows(results, elapsed, contentLength);
        attackLogger.logResponse(requestId, SEARCH_PATH, correlation, statusCode,
                resultType.name(), "rows=" + results.size() + " elapsed=" + elapsed);
        body = results;
    } catch (Exception e) {
        long elapsed = System.currentTimeMillis() - start;
        String fullError = extractFullErrorChain(e);  // ← cause 체인까지 포함
        resultType = sqliEvaluator.evaluateError(fullError);
        input = SqliInput.ofError(fullError, elapsed);
        attackLogger.logResponse(requestId, SEARCH_PATH, correlation, statusCode,
                resultType.name(), "error=" + fullError);
        body = Map.of("error", e.getMessage(), "sql_state", e.getClass().getSimpleName());
    }
    long latencyMs = System.currentTimeMillis() - start;

    // Validator 결과는 validation 에만 기록되고 응답 본문/상태코드에는 영향을 주지 않는다
    AttackObservation observation = sqliValidator.observe(
            new ValidationContext<>(requestId, correlation, requestTime, statusCode, input), resultType);
    HttpExchange exchange = new HttpExchange(requestTime, "GET", SEARCH_PATH,
            correlation.getUserAgent(), args, statusCode, latencyMs, bodyLength(body));
    attackLogger.logHttpActivity(requestId, exchange, correlation, observation);
    return body;
}

// 실제 응답과 같은 Spring JsonMapper로 직렬화한 바이트 수 (실패 시 -1)
private long bodyLength(Object body) {
    try {
        return objectMapper.writeValueAsBytes(body).length;
    } catch (JacksonException e) {
        return -1;
    }
}

private String extractFullErrorChain(Throwable e) {
    StringBuilder sb = new StringBuilder();
    Throwable cur = e;
    while (cur != null) {
        if (cur.getMessage() != null) sb.append(cur.getMessage()).append(" | ");
        cur = cur.getCause();
    }
    return sb.toString();
}
}