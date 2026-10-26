package com.capstone.vuln.correlation;

import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wazuh/Suricata alert 1건
 * - alertTime: alert 생성 시각 (Wazuh `timestamp`) — MTTD 기준
 * - searchableTime: indexer 에서 처음 검색된 시각 (없으면 null) — Ingestion Lag 기준
 * - rid/opId/abilityId/srcIp/endpoint: Wazuh 는 `data.*` 에 실린 앱 이벤트 값, 없으면 null
 * - idSource: opId/abilityId 를 어느 채널에서 얻었는지 (`correlation.source`)
 * - username: `data.http_request.args` 의 username 값 (없으면 null — 예: Suricata). BF/스프레이 계정 구분은 이 값만 쓴다
 * - control: 알림을 낸 통제 (R14). NIDS 는 rid 가 alert 원문 값이 아니라 R14 c 로 연결한 시도의 rid 이다
 */
public record AlertEvent(String ruleId, String technique, Instant alertTime, Instant searchableTime,
                         String rid, String opId, String abilityId, String srcIp, String endpoint,
                         CorrelationSource idSource, String username, DetectionControl control) {

    private static final Pattern USERNAME_ARG = Pattern.compile("(?:^|&)username=([^&]+)");

    /** 앱 로그 룰 alert (R14 이전과 같은 형태) */
    public AlertEvent(String ruleId, String technique, Instant alertTime, Instant searchableTime,
                      String rid, String opId, String abilityId, String srcIp, String endpoint,
                      CorrelationSource idSource, String username) {
        this(ruleId, technique, alertTime, searchableTime, rid, opId, abilityId, srcIp, endpoint, idSource, username,
                DetectionControl.APP_RULE);
    }

    /** username 을 모르는 앱 로그 룰 alert */
    public AlertEvent(String ruleId, String technique, Instant alertTime, Instant searchableTime,
                      String rid, String opId, String abilityId, String srcIp, String endpoint,
                      CorrelationSource idSource) {
        this(ruleId, technique, alertTime, searchableTime, rid, opId, abilityId, srcIp, endpoint, idSource, null);
    }

    /**
     * NIDS alert (R14 c) — ruleId = signature_id, technique·rid·endpoint = 연결된 시도의 값.
     * 엔진은 이 rid 의 그룹에만 UA_FALLBACK 으로 연결한다(시간창만으로 엮지 않음).
     */
    public static AlertEvent nids(String sid, String technique, Instant alertTime, Instant searchableTime,
                                  String attemptRid, String srcIp, String endpoint) {
        return new AlertEvent(sid, technique, alertTime, searchableTime, attemptRid, null, null, srcIp, endpoint,
                CorrelationSource.UA_FALLBACK, null, DetectionControl.NIDS);
    }

    /** http_request.args (예: "username=admin") 에서 username 값을 꺼낸다. 없거나 빈 값이면 null */
    public static String usernameFromArgs(String args) {
        if (args == null) {
            return null;
        }
        Matcher m = USERNAME_ARG.matcher(args);
        return m.find() ? m.group(1) : null;
    }
}
