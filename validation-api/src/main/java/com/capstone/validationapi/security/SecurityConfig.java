package com.capstone.validationapi.security;

import com.capstone.validationapi.ValidationApiProperties;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * ADR-S4-02 D6: SecurityFilterChain 2개.
 *  · @Order(1) /api/**  — Bearer(stateless, 세션 새로 안 만듦) 또는 기존 세션. 401 problem+json.
 *  · @Order(2) UI       — formLogin + 세션 쿠키 + CSRF. 무인증은 /actuator/health 하나.
 * D9 CSP: default-src 'self'; script-src 'self'(unsafe-eval 없음); img-src 'self' data:; frame-ancestors 'none'.
 */
@Configuration
public class SecurityConfig {

    // D9 CSP (ADR-S4-02). 인라인 style·script·eval 을 쓰지 않는 자산만 서빙 → script-src·style-src 모두 'self'.
    // (S4-6: vega 차트 제거로 인라인 style 주입원 없음. 파비콘은 data: SVG → img-src data:.)
    static final String CSP =
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            + "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 대시보드 로그인 사용자 1명(비밀번호는 bcrypt 해시로 .env 주입 — 평문 저장 안 함).
     * 해시가 없으면(미설정) 사용자를 등록하지 않는다 → formLogin 은 항상 실패(fail-closed).
     */
    @Bean
    public UserDetailsService userDetailsService(
            @Value("${validationapi.ui.username:viewer}") String username,
            @Value("${validationapi.ui.password-bcrypt:}") String bcryptHash) {
        if (bcryptHash == null || bcryptHash.isBlank()) {
            return new InMemoryUserDetailsManager();
        }
        return new InMemoryUserDetailsManager(
                User.withUsername(username).password(bcryptHash).roles("VIEWER").build());
    }

    @Bean
    public ProblemDetailAuthenticationEntryPoint apiEntryPoint(ObjectMapper mapper) {
        return new ProblemDetailAuthenticationEntryPoint(mapper);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http,
                                              ValidationApiProperties props,
                                              ProblemDetailAuthenticationEntryPoint entryPoint) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                // 세션을 새로 만들지 않음. 기존 세션(UI 로그인)이 있으면 사용.
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .csrf(csrf -> csrf.disable())        // /api 는 GET 전용(D4) → 상태 변경 없음
                .httpBasic(h -> h.disable())
                .formLogin(f -> f.disable())
                .logout(l -> l.disable())
                .anonymous(Customizer.withDefaults())
                // Bearer 필터는 @Bean 아님(자동 등록 방지), UsernamePasswordAuthenticationFilter 앞(LogoutFilter 뒤)
                .addFilterBefore(new BearerTokenAuthenticationFilter(props.tokenList()),
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint))
                .headers(h -> h
                        .contentSecurityPolicy(c -> c.policyDirectives(CSP))
                        .frameOptions(fo -> fo.deny()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain uiFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/login", "/login/**", "/error", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                // 인라인 없는 커스텀 로그인 페이지(LoginController) — CSP 준수
                .formLogin(f -> f.loginPage("/login").defaultSuccessUrl("/", true).permitAll())
                .logout(Customizer.withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                // UI 폼 CSRF 유지. 평문 핸들러 — 커스텀 로그인 페이지가 렌더한 raw 토큰이 POST 에서 검증되게 한다.
                // (기본 XOR/BREACH 핸들러는 masked 값을 기대 → 커스텀 폼의 raw 토큰과 불일치로 403. 로컬 랩에서 BREACH 는 미적용.)
                .csrf(c -> c.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .headers(h -> h
                        .contentSecurityPolicy(c -> c.policyDirectives(CSP))
                        .frameOptions(fo -> fo.deny()));
        return http.build();
    }
}
