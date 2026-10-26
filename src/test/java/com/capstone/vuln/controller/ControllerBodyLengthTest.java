package com.capstone.vuln.controller;

import com.capstone.vuln.auth.BruteForceValidator;
import com.capstone.vuln.correlation.CalderaCorrelationExtractor;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.file.PathTraversalValidator;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.logging.HttpExchange;
import com.capstone.vuln.product.SqliValidator;
import com.capstone.vuln.repository.VulnRepository;
import com.capstone.vuln.ssrf.SsrfValidator;
import com.capstone.vuln.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * G2 — OCSF http_response.body_length 골든 (S3 Boot 4.1 업그레이드 전 기준선, 3.5.13).
 *
 * <p>DB 없는 웹 슬라이스: 실제 컨트롤러·Validator·AttackLogger 와 application.yaml 의 Spring Jackson 설정
 * (spring.jackson.serialization.indent-output: true) 로 요청을 처리하고, AttackLogger 에 넘어간 body_length 를 본다.
 * DB 는 JdbcTemplate·VulnRepository 모킹으로 대신한다.
 *
 * <p>기대값 60·141 은 S4-STACK-2-SMOKE 실측(BF 실패 401, SQLi keyword=' 의 SQL 오류 응답)과 같다.
 * 함께 "로그 body_length = 실제 응답 바이트 수" 를 확인한다(ADR-S4-03 슬라이스 3 기준 7 허용 조건 ②).
 */
@WebMvcTest(controllers = {ProductController.class, AuthController.class, FileController.class, PreviewController.class})
@Import({AttackLogger.class, CalderaCorrelationExtractor.class, SqliEvaluator.class, SqliValidator.class,
        BruteForceValidator.class, PathTraversalValidator.class, SsrfValidator.class})
class ControllerBodyLengthTest {

    private static final String CALDERA_UA = "Caldera/qpiere/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c";

    @Autowired private MockMvc mvc;

    @MockitoSpyBean private AttackLogger attackLogger;
    @MockitoBean private VulnRepository vulnRepository;
    @MockitoBean private JdbcTemplate jdbcTemplate;
    @MockitoBean private JwtUtil jwtUtil;

    /** 요청 1건이 AttackLogger.logHttpActivity 로 넘긴 HttpExchange */
    private HttpExchange loggedExchange() {
        ArgumentCaptor<HttpExchange> exchange = ArgumentCaptor.forClass(HttpExchange.class);
        verify(attackLogger).logHttpActivity(anyString(), exchange.capture(), any(CorrelationInfo.class), any());
        return exchange.getValue();
    }

    private void assertBodyLength(long expected, MvcResult result) {
        HttpExchange exchange = loggedExchange();
        assertEquals(expected, exchange.bodyLength(), "로그 body_length 골든");
        assertEquals(result.getResponse().getContentAsByteArray().length, exchange.bodyLength(),
                "로그 body_length = 실제 응답 바이트 수");
    }

    @Test
    void sqliErrorResponseIs141Bytes() throws Exception {
        // 2-SMOKE SQLi(keyword=') 와 같은 오류: JdbcTemplate 이 던지는 BadSqlGrammarException(메시지 = task; bad SQL grammar [sql])
        when(vulnRepository.executeRawQuery(anyString())).thenAnswer(inv -> {
            throw new BadSqlGrammarException("StatementCallback", inv.getArgument(0),
                    new SQLException("Unterminated string literal started at position 43"));
        });

        MvcResult result = mvc.perform(get("/api/products/search").param("keyword", "'")
                .header("User-Agent", CALDERA_UA)).andReturn();

        assertEquals(200, result.getResponse().getStatus());
        assertBodyLength(141, result);
    }

    @Test
    void loginFailureResponseIs60Bytes() throws Exception {
        // 모킹된 JdbcTemplate.queryForList 는 빈 목록 → 자격증명 불일치(401)
        MvcResult result = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"user1\",\"password\":\"wrong\"}")).andReturn();

        assertEquals(401, result.getResponse().getStatus());
        assertBodyLength(60, result);
    }

    @Test
    void fileNotFoundBodyLengthEqualsResponseBytes() throws Exception {
        MvcResult result = mvc.perform(get("/api/files/download").param("filename", "golden-missing-file.txt"))
                .andReturn();

        assertEquals(404, result.getResponse().getStatus());
        HttpExchange exchange = loggedExchange();
        assertEquals(result.getResponse().getContentAsByteArray().length, exchange.bodyLength(),
                "로그 body_length = 실제 응답 바이트 수");
    }

    @Test
    void ssrfSchemeBlockedResponseIs32Bytes() throws Exception {
        // 스킴 가드 — 아웃바운드 요청 없음. 본문 "Only http/https URLs are allowed"
        MvcResult result = mvc.perform(get("/api/preview").param("url", "file:///etc/hostname")).andReturn();

        assertEquals(400, result.getResponse().getStatus());
        assertBodyLength(32, result);
    }
}
