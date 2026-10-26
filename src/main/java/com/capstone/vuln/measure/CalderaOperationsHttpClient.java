package com.capstone.vuln.measure;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Caldera REST API v2 클라이언트(측정 도구 전용) — 인증은 기존 상관분석 클라이언트와 동일하게
 * 헤더 KEY 로 하고, 키는 환경변수(APP_CALDERA_APIKEY)에서만 주입받는다(어떤 파일에도 쓰지 않음).
 *
 * <p>생성 바디의 중첩-id 폼(adversary.adversary_id / planner.id / source.id)은 라이브 스모크에서
 * 수용 확인됨. 고정 필드는 측정 격리를 위해 여기서 고정한다:
 * state=running, auto_close=true, autonomous=1, obfuscator=plain-text(난독화 시 OCSF 파싱·상관 깨짐),
 * jitter=2/8, visibility=51.
 *
 * <p>poll 은 operation state 만 읽어 반환한다(chain 추론 없음 — 완료 판정은 OperationRunner 가 state 로만).
 */
public class CalderaOperationsHttpClient implements CalderaOperations {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final RestClient rest;

    public CalderaOperationsHttpClient(String baseUrl, String apiKey) {
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
    public String create(OperationCreateRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", request.name());
        body.put("adversary", Map.of("adversary_id", request.adversaryId()));
        body.put("planner", Map.of("id", request.plannerId()));
        body.put("source", Map.of("id", request.sourceId()));
        body.put("group", request.group());
        body.put("state", "running");
        body.put("auto_close", true);
        body.put("autonomous", 1);
        body.put("obfuscator", "plain-text");
        body.put("jitter", "2/8");
        body.put("visibility", 51);

        String response;
        try {
            response = rest.post()
                    .uri("/api/v2/operations")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(String.class);
        } catch (RestClientResponseException e) {
            throw new IllegalStateException(
                    "Caldera operation 생성 실패: HTTP " + e.getStatusCode().value()
                            + " body=" + e.getResponseBodyAsString(), e);
        }
        String opId = readTree(response).path("id").asString("");
        if (opId.isBlank()) {
            throw new IllegalStateException("Caldera operation 생성 응답에 id 가 없음: " + response);
        }
        return opId;
    }

    @Override
    public String poll(String opId) {
        String response;
        try {
            response = rest.get()
                    .uri("/api/v2/operations/{id}", opId)
                    .retrieve()
                    .body(String.class);
        } catch (RestClientResponseException e) {
            throw new IllegalStateException(
                    "Caldera operation 조회 실패: HTTP " + e.getStatusCode().value()
                            + " opId=" + opId, e);
        }
        return readTree(response).path("state").asString("");
    }

    private static JsonNode readTree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JacksonException e) {
            throw new IllegalStateException("Caldera 응답 파싱 실패", e);
        }
    }
}
