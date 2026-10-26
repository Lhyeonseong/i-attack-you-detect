package com.capstone.validationapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * ADR-S4-02 D6: Authorization: Bearer 토큰만 받는다(쿼리 파라미터·URL 금지 → 서버 로그 노출 방지).
 * 비교는 상수 시간(MessageDigest.isEqual). 실패/예외는 인증 안 함(fail-closed) → EntryPoint 가 401.
 * 이미 인증(세션)이 있으면 그대로 둔다(D6: /api 는 Bearer 또는 세션, 세션을 새로 만들지 않음).
 *
 * <p>@Component·@Bean 으로 선언하지 않는다(서블릿 자동 등록 방지, D6). SecurityConfig 가 직접 인스턴스화.
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final List<byte[]> allowed;

    public BearerTokenAuthenticationFilter(List<String> tokens) {
        this.allowed = tokens.stream().map(t -> t.getBytes(StandardCharsets.UTF_8)).toList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                String header = request.getHeader("Authorization");
                if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
                    byte[] presented = header.substring(7).trim().getBytes(StandardCharsets.UTF_8);
                    if (matchesAny(presented)) {
                        var auth = UsernamePasswordAuthenticationToken.authenticated(
                                "api-client", null, AuthorityUtils.createAuthorityList("ROLE_API"));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                }
            }
        } catch (RuntimeException ex) {
            // fail-closed: 인증 설정 안 함(= 미인증) → EntryPoint 401
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }

    /** 상수 시간 비교 — 모든 후보와 비교해 타이밍 노출을 줄인다. */
    private boolean matchesAny(byte[] presented) {
        boolean ok = false;
        for (byte[] candidate : allowed) {
            if (MessageDigest.isEqual(candidate, presented)) {
                ok = true;
            }
        }
        return ok;
    }
}
