package com.capstone.vuln.logging;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.evaluator.SqliResultType;
import com.capstone.vuln.product.SqliInput;
import com.capstone.vuln.product.SqliValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackLoggerHttpActivityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant TIME = Instant.parse("2026-10-10T00:00:00Z");

    // observe()는 evaluator를 쓰지 않으므로 임계값 주입 없이 생성
    private final SqliValidator validator = new SqliValidator(new SqliEvaluator());

    private final CorrelationInfo correlation = new CorrelationInfo("op-1", "T1190", "ab-1",
            CorrelationSource.HEADER, "10.0.0.5", "Caldera/op-1/T1190/ab-1");

    private final HttpExchange exchange = new HttpExchange(TIME, "GET", "/api/products/search",
            "Caldera/op-1/T1190/ab-1", "keyword=' OR 1=1--", 200, 42, 1234);

    private JsonNode render(SqliResultType resultType) throws Exception {
        ValidationContext<SqliInput> ctx = new ValidationContext<>("rid-1", correlation, TIME, 200,
                SqliInput.ofRows(List.of(), 42, 1234));
        AttackObservation observation = validator.observe(ctx, resultType);
        String json = AttackLogger.toHttpActivityJson("rid-1", exchange, correlation, observation);

        assertFalse(json.contains("\n"), "JSON log must be a single line");
        return MAPPER.readTree(json);
    }

    @ParameterizedTest
    @CsvSource({
            "UNION_DATA_LEAKED, SUCCEEDED, DATA_EXPOSURE",
            "SQL_ERROR_EXPOSED, SUCCEEDED, RESPONSE_PATTERN",
            "TIME_BASED_DELAY,  EXECUTED,  TIMING",
            "LENGTH_ANOMALY,    EXECUTED,  TIMING",
            "NORMAL,            FAILED,    ''",
            "UNKNOWN,           UNKNOWN,   ''"
    })
    void resultTypeMapsToValidationOutcomeAndEvidence(SqliResultType resultType, String outcome,
                                                      String evidenceKind) throws Exception {
        JsonNode validation = render(resultType).get("validation");

        assertEquals(outcome, validation.get("outcome").asText());
        JsonNode evidence = validation.get("evidence");
        if (evidenceKind == null || evidenceKind.isEmpty()) {
            assertEquals(0, evidence.size());
        } else {
            assertEquals(1, evidence.size());
            assertEquals(Set.of("kind"), fieldNames(evidence.get(0)));
            assertEquals(evidenceKind, evidence.get(0).get("kind").asText());
        }
        assertEquals("v1", validation.get("validator_version").asText());
        assertEquals("T1190", validation.get("technique_id").asText());
    }

    @Test
    void httpResponseContainsOnlyRawResponseValues() throws Exception {
        JsonNode root = render(SqliResultType.UNION_DATA_LEAKED);
        JsonNode response = root.get("http_response");

        assertEquals(Set.of("code", "latency_ms", "body_length"), fieldNames(response));
        assertEquals(200, response.get("code").asInt());
        assertEquals(42, response.get("latency_ms").asLong());
        assertEquals(1234, response.get("body_length").asLong());

        // validation 값이 http_request / http_response 쪽으로 새어들어가지 않아야 한다
        String requestAndResponse = root.get("http_request").toString() + response;
        for (String leaked : List.of("SUCCEEDED", "DATA_EXPOSURE", "UNION_DATA_LEAKED", "outcome", "evidence")) {
            assertFalse(requestAndResponse.contains(leaked), "leaked into http_*: " + leaked);
        }
    }

    @Test
    void envelopeFollowsOcsfHttpActivityWithoutDetection() throws Exception {
        JsonNode root = render(SqliResultType.NORMAL);

        assertEquals(List.of("time", "metadata", "class_uid", "class_name", "activity_id", "rid",
                        "src_endpoint", "http_request", "http_response", "validation", "correlation"),
                new ArrayList<>(fieldNames(root)));
        assertFalse(root.has("detection"));

        assertEquals(TIME.toEpochMilli(), root.get("time").asLong());
        assertEquals("1.9.0", root.at("/metadata/version").asText());
        assertEquals("attack_http_activity", root.at("/metadata/log_name").asText());
        assertEquals(4002, root.get("class_uid").asInt());
        assertEquals("HTTP Activity", root.get("class_name").asText());
        assertEquals(3, root.get("activity_id").asInt());
        assertEquals("rid-1", root.get("rid").asText());
        assertEquals("10.0.0.5", root.at("/src_endpoint/ip").asText());

        assertEquals("GET", root.at("/http_request/http_method").asText());
        assertEquals("/api/products/search", root.at("/http_request/url/path").asText());
        assertEquals("Caldera/op-1/T1190/ab-1", root.at("/http_request/user_agent").asText());
        assertEquals("keyword=' OR 1=1--", root.at("/http_request/args").asText());

        assertEquals("op-1", root.at("/correlation/op_id").asText());
        assertEquals("ab-1", root.at("/correlation/ability_id").asText());
        assertEquals("HEADER", root.at("/correlation/source").asText());
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new LinkedHashSet<>();
        node.propertyNames().forEach(names::add);
        assertTrue(node.isObject());
        return names;
    }
}
