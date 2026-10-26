package com.capstone.vuln.measure;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Duration;

/**
 * Caldera op JSON(facts 포함) 조회 — S3-3 과 동일한 헤더 KEY 인증 방식(측정 전용 클라이언트).
 * 키는 env(APP_CALDERA_APIKEY)에서만 주입받는다(어떤 파일에도 쓰지 않음).
 */
public class CalderaOperationFactsSource implements OperationFactsSource {

    private final RestClient rest;

    public CalderaOperationFactsSource(String baseUrl, String apiKey) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(10));
        this.rest = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(factory)
                .defaultHeader("KEY", apiKey)
                .build();
    }

    @Override
    public String fetchOperationJson(String opId) {
        try {
            return rest.get()
                    .uri("/api/v2/operations/{id}", opId)
                    .retrieve()
                    .body(String.class);
        } catch (RestClientResponseException e) {
            throw new IllegalStateException(
                    "Caldera operation facts 조회 실패: HTTP " + e.getStatusCode().value()
                            + " opId=" + opId, e);
        }
    }
}
