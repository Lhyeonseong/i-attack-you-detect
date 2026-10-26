package com.capstone.vuln.measure;

import tools.jackson.databind.JsonNode;

/** 수집기 공용 JSON 텍스트 추출 — 누락/JSON null/문자열 "null"/공백을 모두 자바 null 로 정규화(S3-2 특이필드). */
final class MeasureJson {

    private MeasureJson() {
    }

    static String text(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        return normalize(node.asString());
    }

    /** 문자열 값 정규화 — null/공백/"null" 을 자바 null 로 (파생 문자열, 예: args 에서 뽑은 username 에도 적용). */
    static String normalize(String value) {
        return (value == null || value.isBlank() || "null".equals(value)) ? null : value;
    }
}
