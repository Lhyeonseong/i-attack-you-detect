package com.capstone.vuln.controller;

import com.capstone.vuln.auth.BruteForceValidator;
import com.capstone.vuln.correlation.CalderaCorrelationExtractor;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.file.PathTraversalValidator;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.product.SqliValidator;
import com.capstone.vuln.repository.VulnRepository;
import com.capstone.vuln.ssrf.SsrfValidator;
import com.capstone.vuln.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * G3 — DB 없이 도는 웹 계층 배선 테스트.
 *
 * <p>전체 컨텍스트 테스트(VulnerableWebappApplicationTests)는 PostgreSQL 이 없으면 skip 되므로, 컨트롤러 4개와
 * 그 의존성이 실제로 엮이는지를 여기서 따로 본다. 특히 Product/AuthController 는 Spring 자동설정 ObjectMapper 빈을
 * 주입받아 body_length 를 계산한다 — 그 빈이 바뀌거나 사라지면(Boot 4 의 Jackson 3 전환) 이 테스트가 먼저 깨진다.
 */
@WebMvcTest(controllers = {ProductController.class, AuthController.class, FileController.class, PreviewController.class})
@Import({AttackLogger.class, CalderaCorrelationExtractor.class, SqliEvaluator.class, SqliValidator.class,
        BruteForceValidator.class, PathTraversalValidator.class, SsrfValidator.class})
class WebLayerWiringTest {

    @Autowired private ApplicationContext context;

    @MockitoBean private VulnRepository vulnRepository;
    @MockitoBean private JdbcTemplate jdbcTemplate;
    @MockitoBean private JwtUtil jwtUtil;

    @Test
    void allFourControllersAreWired() {
        assertNotNull(context.getBean(ProductController.class));
        assertNotNull(context.getBean(AuthController.class));
        assertNotNull(context.getBean(FileController.class));
        assertNotNull(context.getBean(PreviewController.class));
    }

    @Test
    void controllersUseTheSpringConfiguredObjectMapper() {
        JsonMapper springMapper = context.getBean(JsonMapper.class);

        assertSame(springMapper, ReflectionTestUtils.getField(context.getBean(ProductController.class), "objectMapper"));
        assertSame(springMapper, ReflectionTestUtils.getField(context.getBean(AuthController.class), "objectMapper"));
        // application.yaml spring.jackson.serialization.indent-output: true 가 그 빈에 적용돼 있어야 body_length 가 응답과 같다
        assertTrue(springMapper.isEnabled(SerializationFeature.INDENT_OUTPUT));
    }
}
