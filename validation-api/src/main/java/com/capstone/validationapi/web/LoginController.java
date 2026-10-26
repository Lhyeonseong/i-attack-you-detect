package com.capstone.validationapi.web;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class LoginController {

    @GetMapping("/login")
    @ResponseBody
    public ResponseEntity<String> login(HttpServletRequest request,
                                        @RequestParam(required = false) String error,
                                        @RequestParam(required = false) String logout)
            throws IOException {

        CsrfToken token =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        String csrf = token != null ? token.getToken() : "";

        String noticeClass = "";
        String noticeMessage = "";

        if (error != null) {
            noticeClass = "show";
            noticeMessage = "아이디 또는 비밀번호가 올바르지 않습니다.";
        } else if (logout != null) {
            noticeClass = "show logout";
            noticeMessage = "로그아웃되었습니다.";
        }

        String html;
        ClassPathResource resource =
                new ClassPathResource("login/login.html");

        try (var in = resource.getInputStream()) {
            html = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }

        html = html
                .replace("__CSRF__", escape(csrf))
                .replace("__NOTICE_CLASS__", escape(noticeClass))
                .replace("__NOTICE_MESSAGE__", escape(noticeMessage));

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    private static String escape(String s) {
        return s
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
