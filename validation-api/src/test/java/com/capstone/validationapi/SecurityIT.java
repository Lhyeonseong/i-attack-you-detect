package com.capstone.validationapi;

import com.capstone.validationapi.support.AbstractApiIT;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ADR-S4-02 D6/D9 보안 계약. */
class SecurityIT extends AbstractApiIT {

    @Autowired
    MockMvc mvc;

    @Test
    void unauthApiReturns401ProblemJson() throws Exception {
        mvc.perform(get("/api/v1/meta"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
    }

    @Test
    void wrongBearerReturns401() throws Exception {
        mvc.perform(get("/api/v1/meta").header("Authorization", "Bearer wrong-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void queryParamTokenIsIgnored() throws Exception {
        // ?token= 은 무시 → 여전히 401(헤더만 인정)
        mvc.perform(get("/api/v1/meta").param("token", BEARER))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validBearerReturns200() throws Exception {
        mvc.perform(get("/api/v1/meta").header("Authorization", "Bearer " + BEARER))
                .andExpect(status().isOk());
    }

    @Test
    void healthIsUnauthenticated() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void uiUnauthenticatedRedirectsToLogin() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void loginThenApiWithSessionReturns200() throws Exception {
        MvcResult login = mvc.perform(formLogin("/login").user(UI_USER).password(UI_PASSWORD))
                .andExpect(authenticated())
                .andReturn();
        HttpSession session = login.getRequest().getSession(false);
        mvc.perform(get("/api/v1/meta").session((org.springframework.mock.web.MockHttpSession) session))
                .andExpect(status().isOk());
    }

    @Test
    void customLoginFormCsrfLogsIn() throws Exception {
        // 커스텀 로그인 페이지가 렌더한 raw _csrf 로 실제 POST 로그인(formLogin() 테스트는 자체 CSRF라 이 경로를 안 거침).
        MvcResult g = mvc.perform(get("/login")).andExpect(status().isOk()).andReturn();
        String html = g.getResponse().getContentAsString();
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(html);
        assertTrue(m.find(), "로그인 페이지에 _csrf hidden input 없음");
        HttpSession session = g.getRequest().getSession(false);
        mvc.perform(post("/login")
                        .param("username", UI_USER).param("password", UI_PASSWORD).param("_csrf", m.group(1))
                        .session((org.springframework.mock.web.MockHttpSession) session))
                .andExpect(authenticated());
    }

    @Test
    void loginPageHasCspAndNoInlineStyleOrScript() throws Exception {
        MvcResult res = mvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Content-Security-Policy"))
                .andReturn();
        String csp = res.getResponse().getHeader("Content-Security-Policy");
        assertTrue(csp.contains("script-src 'self'"), csp);
        assertFalse(csp.contains("unsafe-eval"), csp);
        String body = res.getResponse().getContentAsString();
        assertFalse(body.contains("<style"), "로그인 페이지에 인라인 style 없음");
        assertFalse(body.contains("<script"), "로그인 페이지에 인라인 script 없음");
    }

    @Test
    void apiResponseCarriesCspWithoutUnsafeEval() throws Exception {
        MvcResult res = mvc.perform(get("/api/v1/meta").header("Authorization", "Bearer " + BEARER))
                .andExpect(status().isOk())
                .andExpect(header().exists("Content-Security-Policy"))
                .andReturn();
        String csp = res.getResponse().getHeader("Content-Security-Policy");
        assertTrue(csp.contains("script-src 'self'"), csp);
        assertFalse(csp.contains("unsafe-eval"), csp);
    }
}
