package com.capstone.validationapi.error;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * ADR-S4-02 D4: 모든 오류를 application/problem+json(RFC 9457)으로. 스택트레이스·SQL·내부 정보 미노출(API8).
 * A10 fail-closed: DB 오류·statement_timeout 초과 시 503, 부분/이전 값 반환 안 함.
 * (인증 실패 401 은 D6 ProblemDetailAuthenticationEntryPoint 가 담당.)
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiExceptions.NotValidRunException.class)
    public ProblemDetail notValidRun(ApiExceptions.NotValidRunException ex) {
        return problem(HttpStatus.CONFLICT, "Run not VALID", ex.getMessage());
    }

    @ExceptionHandler(ApiExceptions.DefinitionMismatchException.class)
    public ProblemDetail definitionMismatch(ApiExceptions.DefinitionMismatchException ex) {
        return problem(HttpStatus.CONFLICT, "Definition version mismatch", ex.getMessage());
    }

    @ExceptionHandler({ApiExceptions.BadRequestException.class, IllegalArgumentException.class,
            MethodArgumentTypeMismatchException.class, MissingServletRequestParameterException.class})
    public ProblemDetail badRequest(Exception ex) {
        return problem(HttpStatus.BAD_REQUEST, "Bad request", safeDetail(ex));
    }

    @ExceptionHandler(ApiExceptions.NotFoundException.class)
    public ProblemDetail notFound(ApiExceptions.NotFoundException ex) {
        return problem(HttpStatus.NOT_FOUND, "Not found", ex.getMessage());
    }

    /** DB 오류·statement_timeout → 503. 내부 메시지 노출 안 함(A10·API8). */
    @ExceptionHandler(DataAccessException.class)
    public ProblemDetail dataAccess(DataAccessException ex) {
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "Data store unavailable",
                "조회를 완료할 수 없습니다");
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail generic(Exception ex) {
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error", "요청을 처리할 수 없습니다");
    }

    private static ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail == null ? "" : detail);
        pd.setTitle(title);
        return pd;
    }

    /** 허용 목록 위반 등은 메시지를 그대로 쓰되, 그 외는 일반화. */
    private static String safeDetail(Exception ex) {
        if (ex instanceof ApiExceptions.BadRequestException || ex instanceof IllegalArgumentException) {
            return ex.getMessage();
        }
        if (ex instanceof MethodArgumentTypeMismatchException m) {
            return "파라미터 형식 오류: " + m.getName();
        }
        if (ex instanceof MissingServletRequestParameterException m) {
            return "필수 파라미터 누락: " + m.getParameterName();
        }
        return "요청이 올바르지 않습니다";
    }
}
