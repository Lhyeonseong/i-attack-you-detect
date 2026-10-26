package com.capstone.vuln.correlation;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Caldera REST API v2 클라이언트 — GET /api/v2/operations (헤더 KEY)
 */
public class CalderaOperationsHttpClient implements CalderaOperationsClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final RestClient rest;

    public CalderaOperationsHttpClient(String baseUrl, String apiKey) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(5));
        this.rest = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(factory)
                .defaultHeader("KEY", apiKey)
                .build();
    }

    @Override
    public List<OperationLink> fetchLinks() {
        String body = rest.get().uri("/api/v2/operations").retrieve().body(String.class);
        return parseLinks(body);
    }

    static List<OperationLink> parseLinks(String json) {
        JsonNode operations;
        try {
            operations = MAPPER.readTree(json);
        } catch (JacksonException e) {
            throw new IllegalStateException("Caldera operations 응답 파싱 실패", e);
        }
        List<OperationLink> links = new ArrayList<>();
        for (JsonNode op : operations) {
            String opId = op.path("id").asString();
            for (JsonNode link : op.path("chain")) {
                Instant decide = instantOrNull(link.path("decide"));
                if (decide == null) {
                    continue;
                }
                links.add(new OperationLink(opId,
                        link.path("paw").asString(),
                        link.path("ability").path("ability_id").asString(),
                        decide,
                        instantOrNull(link.path("finish"))));
            }
        }
        return links;
    }

    private static Instant instantOrNull(JsonNode node) {
        String text = node.asString("");
        return text.isBlank() || "null".equals(text) ? null : Instant.parse(text);
    }
}
