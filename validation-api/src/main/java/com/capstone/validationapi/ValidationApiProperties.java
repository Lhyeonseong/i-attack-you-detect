package com.capstone.validationapi;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * 앱 설정(ADR-S4-02 D4·D6). bearer-tokens 는 쉼표 구분(.env VALIDATION_API_BEARER_TOKENS).
 */
@ConfigurationProperties(prefix = "validationapi")
public record ValidationApiProperties(
        String bearerTokens,
        Integer maxLimit,
        Integer defaultLimit) {

    public ValidationApiProperties {
        if (maxLimit == null) {
            maxLimit = 500;
        }
        if (defaultLimit == null) {
            defaultLimit = 200;
        }
    }

    /** 공백·빈 토큰 제거한 토큰 목록. */
    public List<String> tokenList() {
        if (bearerTokens == null || bearerTokens.isBlank()) {
            return List.of();
        }
        return List.of(bearerTokens.split(",")).stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
