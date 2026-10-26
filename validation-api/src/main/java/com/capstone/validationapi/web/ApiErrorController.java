package com.capstone.validationapi.web;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.stereotype.Controller;

/**
 * 일관된 오류 처리(ADR-S4-02 D4). Whitelabel 대신 /error 를 직접 처리:
 *  · /api* 또는 Accept=json → application/problem+json (내부 정보 미노출)
 *  · 그 외(UI) → 인라인 없는 최소 HTML(CSP 준수)
 * CSRF 403·정적 404 등 예외 처리기를 거치지 않는 오류도 여기로 모인다.
 */
@Controller
public class ApiErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<?> handle(HttpServletRequest request) {
        Object sc = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        HttpStatus status = sc instanceof Integer i
                ? (HttpStatus.resolve(i) == null ? HttpStatus.INTERNAL_SERVER_ERROR : HttpStatus.resolve(i))
                : HttpStatus.INTERNAL_SERVER_ERROR;
        Object uri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        String accept = request.getHeader("Accept");
        boolean wantsJson = (uri != null && String.valueOf(uri).startsWith("/api"))
                || (accept != null && accept.contains("json"));

        if (wantsJson) {
            ProblemDetail pd = ProblemDetail.forStatus(status);
            pd.setTitle(status.getReasonPhrase());
            return ResponseEntity.status(status)
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON).body(pd);
        }
        String html = "<!doctype html>\n<html lang=\"ko\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<title>오류 " + status.value() + "</title></head><body><main>"
                + "<h1>" + status.value() + " " + status.getReasonPhrase() + "</h1>"
                + "<p><a href=\"/\">대시보드로 돌아가기</a></p></main></body></html>\n";
        return ResponseEntity.status(status).contentType(MediaType.TEXT_HTML).body(html);
    }
}
