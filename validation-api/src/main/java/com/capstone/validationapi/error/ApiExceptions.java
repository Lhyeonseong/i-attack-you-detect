package com.capstone.validationapi.error;

/** 도메인 예외(ADR-S4-02 D4). 메시지는 사용자 노출 안전(내부 정보 없음). */
public final class ApiExceptions {

    private ApiExceptions() {
    }

    /** 비-VALID run 의 지표 조회 → 409(무결성 상태만, 지표 미반환). */
    public static class NotValidRunException extends RuntimeException {
        public NotValidRunException(String msg) {
            super(msg);
        }
    }

    /** /compare 의 before/after 정의 버전이 다름 → 409. */
    public static class DefinitionMismatchException extends RuntimeException {
        public DefinitionMismatchException(String msg) {
            super(msg);
        }
    }

    /** 허용 목록 밖 입력·형식 오류 → 400. */
    public static class BadRequestException extends RuntimeException {
        public BadRequestException(String msg) {
            super(msg);
        }
    }

    /** 존재하지 않는 run 등 → 404. */
    public static class NotFoundException extends RuntimeException {
        public NotFoundException(String msg) {
            super(msg);
        }
    }
}
