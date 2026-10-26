package com.capstone.vuln.logging;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.Evidence;
import com.capstone.vuln.correlation.CorrelationInfo;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class AttackLogger {

    private static final Logger log = LoggerFactory.getLogger(AttackLogger.class);

    // OCSF JSON 전용 로거 — logback-spring.xml 에서 attack.json.log 로만 출력 (additivity=false)
    private static final Logger activityLog = LoggerFactory.getLogger("attack.http.activity");

    // Spring 자동설정 JsonMapper는 indent-output이 켜져 있어 한 줄 로그가 깨지므로 별도 인스턴스 사용
    private static final ObjectMapper JSON = new ObjectMapper();

    static final String OCSF_VERSION = "1.9.0";
    static final String LOG_NAME = "attack_http_activity";
    static final int HTTP_ACTIVITY_CLASS_UID = 4002;
    static final String HTTP_ACTIVITY_CLASS_NAME = "HTTP Activity";

    /**
     * 요청 진입 시 호출 — correlation 정보와 함께 모든 컨텍스트 기록
     */
    public void logRequest(String requestId, String endpoint, String method,
                           CorrelationInfo correlation, String username, String params) {
        log.info("ATTACK_REQUEST | rid={} | endpoint={} | method={} | opId={} | tech={} | ability={} | source={} | ip={} | ua={} | username={} | params={}",
                requestId, endpoint, method,
                correlation.getOpId(),
                correlation.getTechniqueId(),
                correlation.getAbilityId(),
                correlation.getSource(),
                correlation.getSourceIp(),
                correlation.getUserAgent(),
                username,
                params);
    }

    /**
     * 응답 시 호출 — request_id로 요청 로그와 join 가능
     * correlation을 받아 opId를 응답 로그에도 직접 기록
     *    → 매칭 알고리즘이 시퀀스 묶을 때 join 단계 생략 가능
     */
    public void logResponse(String requestId, String endpoint, CorrelationInfo correlation,
                            int statusCode, String resultType, String resultDetail) {
        log.info("ATTACK_RESPONSE | rid={} | endpoint={} | opId={} | status={} | result_type={} | detail={}",
                requestId, endpoint,
                correlation.getOpId(),
                statusCode, resultType, resultDetail);
    }

    /**
     * OCSF HTTP Activity(class_uid 4002) 한 줄 JSON 로그
     * - http_request / http_response: 요청·응답 원본값만 기록
     * - validation: Validator 관찰 결과만 기록 (탐지 판정은 Wazuh/Suricata 몫이므로 detection 필드는 두지 않는다)
     */
    public void logHttpActivity(String requestId, HttpExchange exchange,
                                CorrelationInfo correlation, AttackObservation observation) {
        try {
            activityLog.info("{}", toHttpActivityJson(requestId, exchange, correlation, observation));
        } catch (JacksonException e) {
            log.warn("ATTACK_HTTP_ACTIVITY serialization failed | rid={} | error={}", requestId, e.getMessage());
        }
    }

    static String toHttpActivityJson(String requestId, HttpExchange exchange,
                                     CorrelationInfo correlation, AttackObservation observation)
            throws JacksonException {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("time", exchange.time().toEpochMilli());
        event.put("metadata", ordered("version", OCSF_VERSION, "log_name", LOG_NAME));
        event.put("class_uid", HTTP_ACTIVITY_CLASS_UID);
        event.put("class_name", HTTP_ACTIVITY_CLASS_NAME);
        event.put("activity_id", activityId(exchange.method()));
        event.put("rid", requestId);
        event.put("src_endpoint", ordered("ip", correlation.getSourceIp()));
        event.put("http_request", ordered(
                "http_method", exchange.method(),
                "url", ordered("path", exchange.path()),
                "user_agent", exchange.userAgent(),
                "args", exchange.args()));
        event.put("http_response", ordered(
                "code", exchange.statusCode(),
                "latency_ms", exchange.latencyMs(),
                "body_length", exchange.bodyLength()));
        event.put("validation", ordered(
                "outcome", observation.outcome().name(),
                "evidence", evidenceKinds(observation.evidence()),
                "validator_version", observation.validatorVersion(),
                "technique_id", observation.techniqueId()));
        event.put("correlation", ordered(
                "op_id", correlation.getOpId(),
                "ability_id", correlation.getAbilityId(),
                "source", correlation.getSource() == null ? null : correlation.getSource().name()));
        return JSON.writeValueAsString(event);
    }

    // OCSF HTTP Activity activity_id
    private static int activityId(String method) {
        if (method == null) return 0;
        return switch (method.toUpperCase()) {
            case "CONNECT" -> 1;
            case "DELETE" -> 2;
            case "GET" -> 3;
            case "HEAD" -> 4;
            case "OPTIONS" -> 5;
            case "POST" -> 6;
            case "PUT" -> 7;
            case "TRACE" -> 8;
            case "PATCH" -> 9;
            default -> 99;
        };
    }

    private static List<Map<String, Object>> evidenceKinds(List<Evidence> evidence) {
        return evidence.stream()
                .map(e -> ordered("kind", e.kind().name()))
                .toList();
    }

    // Map.of는 null 값과 키 순서를 보장하지 않으므로 LinkedHashMap 사용
    private static Map<String, Object> ordered(Object... keyValues) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put((String) keyValues[i], keyValues[i + 1]);
        }
        return map;
    }
}
