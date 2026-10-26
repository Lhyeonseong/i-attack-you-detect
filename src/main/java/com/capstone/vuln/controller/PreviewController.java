package com.capstone.vuln.controller;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.*;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.logging.HttpExchange;
import com.capstone.vuln.ssrf.SsrfInput;
import com.capstone.vuln.ssrf.SsrfValidator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
public class PreviewController {

    private static final String PREVIEW_PATH = "/api/preview";

    // Mock IMDS sentinel — 내부 메타데이터 도달 여부를 응답 본문 원문 없이 판정하기 위한 비밀 아닌 마커
    private static final String IMDS_SENTINEL = "MOCK-IMDS-DO-NOT-USE";

    // 내부 전용 대역/호스트 분류 (loopback, link-local, 사설, 메타데이터 호스트명)
    private static final Pattern INTERNAL_HOST = Pattern.compile(
            "(?i)^(localhost|metadata(\\.google\\.internal)?|127\\..*|::1|\\[::1\\]|169\\.254\\..*|10\\..*|"
                    + "192\\.168\\..*|172\\.(1[6-9]|2\\d|3[01])\\..*)$");

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Autowired private CalderaCorrelationExtractor extractor;
    @Autowired private AttackLogger attackLogger;
    @Autowired private SsrfValidator ssrfValidator;

    /**
     * [VULNERABLE] SSRF - 의도적 아웃바운드 URL 검증 누락
     * - 사용자 제공 url 을 서버가 그대로 fetch 한다 (메타데이터/내부 대역 차단 없음)
     * - 유일한 가드: http/https 스킴만 허용 (file://, gopher:// 등은 BLOCKED)
     */
    @GetMapping("/preview")
    public ResponseEntity<?> preview(@RequestParam String url, HttpServletRequest request) {
        String requestId = UUID.randomUUID().toString();
        Instant requestTime = Instant.now();
        long start = System.currentTimeMillis();
        CorrelationInfo correlation = extractor.extract(request);
        String args = "url=" + url;
        attackLogger.logRequest(requestId, PREVIEW_PATH, "GET", correlation, null, args);

        String host = hostOf(url);
        boolean internal = host != null && INTERNAL_HOST.matcher(host).matches();

        int statusCode;
        String resultType;
        String detail;
        SsrfInput input;
        Object body;

        if (!isHttpScheme(url)) {
            statusCode = 400;
            resultType = "BLOCKED";
            detail = "scheme guard blocked non-http(s) url (host=" + host + ")";
            input = SsrfInput.blocked(host);
            body = "Only http/https URLs are allowed";
        } else {
            try {
                HttpResponse<String> resp = http.send(
                        HttpRequest.newBuilder(URI.create(url))
                                .timeout(Duration.ofSeconds(3))
                                .GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                boolean sentinel = resp.body() != null && resp.body().contains(IMDS_SENTINEL);
                long len = resp.body() == null ? 0 : resp.body().getBytes(StandardCharsets.UTF_8).length;
                statusCode = resp.statusCode();
                resultType = "FETCHED";
                detail = "fetched host=" + host + " code=" + statusCode + " internal=" + internal + " sentinel=" + sentinel;
                input = SsrfInput.fetched(internal, sentinel, host, statusCode, len);
                // [VULNERABLE] 서버가 받은 내부 응답을 그대로 반환 (SSRF 영향)
                body = resp.body();
            } catch (Exception e) {
                statusCode = 502;
                resultType = "ERROR";
                detail = "fetch failed host=" + host + " err=" + e.getClass().getSimpleName();
                input = SsrfInput.error(host);
                body = "Upstream fetch failed";
            }
        }

        attackLogger.logResponse(requestId, PREVIEW_PATH, correlation, statusCode, resultType, detail);
        logHttpActivity(requestId, requestTime, start, correlation, args, statusCode, utf8Length(body), input);
        return ResponseEntity.status(statusCode).body(body);
    }

    private void logHttpActivity(String requestId, Instant requestTime, long start, CorrelationInfo correlation,
                                 String args, int statusCode, long bodyLength, SsrfInput input) {
        long latencyMs = System.currentTimeMillis() - start;
        AttackObservation observation = ssrfValidator.validate(
                new ValidationContext<>(requestId, correlation, requestTime, statusCode, input));
        HttpExchange exchange = new HttpExchange(requestTime, "GET", PREVIEW_PATH,
                correlation.getUserAgent(), args, statusCode, latencyMs, bodyLength);
        attackLogger.logHttpActivity(requestId, exchange, correlation, observation);
    }

    private static boolean isHttpScheme(String url) {
        String u = url == null ? "" : url.trim().toLowerCase();
        return u.startsWith("http://") || u.startsWith("https://");
    }

    private static String hostOf(String url) {
        try {
            return URI.create(url.trim()).getHost();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static long utf8Length(Object body) {
        return body == null ? 0 : body.toString().getBytes(StandardCharsets.UTF_8).length;
    }
}
