package com.capstone.vuln.correlation;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Caldera 공격 식별자 추출 유틸 (하이브리드 방식)
 *
 * 우선순위:
 *   1. Primary: HTTP 헤더 (X-Caldera-Op-Id, X-Caldera-Technique, X-Caldera-Ability)
 *   2. Fallback: User-Agent 정규식 파싱 (Caldera/{opId}/{techId}/{abilityId})
 *   3. Last Resort: 둘 다 실패 시 source=NONE
 */
@Component
public class CalderaCorrelationExtractor {

    @Value("${caldera.header.op-id}")
    private String headerOpId;

    @Value("${caldera.header.technique}")
    private String headerTechnique;

    @Value("${caldera.header.ability}")
    private String headerAbility;

    @Value("${caldera.ua-pattern}")
    private String uaPatternStr;

    private Pattern uaPattern;

    // IPv4-mapped IPv6 패턴: ::ffff:192.168.1.10 형태에서 IPv4 부분만 추출
    private static final Pattern IPV4_MAPPED = Pattern.compile(
            "^::ffff:(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$",
            Pattern.CASE_INSENSITIVE);

    public CorrelationInfo extract(HttpServletRequest request) {
        if (uaPattern == null) {
            uaPattern = Pattern.compile(uaPatternStr);
        }

        String sourceIp = resolveSourceIp(request);
        String userAgent = request.getHeader("User-Agent");

        // 1. Primary: 헤더 추출 시도
        String opId = request.getHeader(headerOpId);
        String techId = request.getHeader(headerTechnique);
        String abilityId = request.getHeader(headerAbility);

        if (opId != null && !opId.isBlank()) {
            return new CorrelationInfo(
                    opId, techId, abilityId,
                    CorrelationSource.HEADER,
                    sourceIp, userAgent
            );
        }

        // 2. Fallback: UA 파싱
        if (userAgent != null && userAgent.startsWith("Caldera/")) {
            Matcher m = uaPattern.matcher(userAgent);
            if (m.find()) {
                return new CorrelationInfo(
                        m.group("opId"),
                        m.group("techId"),
                        m.group("abilityId"),
                        CorrelationSource.UA_FALLBACK,
                        sourceIp, userAgent
                );
            }
        }

        // 3. Last Resort: 둘 다 실패
        return new CorrelationInfo(
                null, null, null,
                CorrelationSource.NONE,
                sourceIp, userAgent
        );
    }

    /**
     * Source IP 추출 + IPv6 정규화
     * - X-Forwarded-For 우선, 없으면 request.getRemoteAddr()
     * - IPv6 표현은 IPv4로 정규화하여 Suricata/Wazuh 로그와 correlation_key 매칭 보장
     *   · ::1               → 127.0.0.1
     *   · 0:0:0:0:0:0:0:1   → 127.0.0.1
     *   · ::ffff:X.X.X.X    → X.X.X.X
     */
    private String resolveSourceIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        String raw;
        if (xff != null && !xff.isBlank()) {
            raw = xff.split(",")[0].trim();
        } else {
            raw = request.getRemoteAddr();
        }
        return normalizeIp(raw);
    }

    /**
     * IPv6 → IPv4 정규화
     * Suricata/Wazuh는 보통 IPv4로 로깅하므로 correlation_key 키 불일치를 막기 위해 통일.
     */
    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) return ip;

        // IPv6 루프백 두 가지 표현 → IPv4 루프백
        if ("::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "127.0.0.1";
        }

        // IPv4-mapped IPv6 → IPv4
        Matcher m = IPV4_MAPPED.matcher(ip);
        if (m.matches()) {
            return m.group(1);
        }

        // 그 외 IPv6 주소는 그대로 반환 (실 외부 IPv6 주소까지 임의 변환하지 않음)
        return ip;
    }
}


