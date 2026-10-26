package com.capstone.vuln.correlation;

import java.time.Instant;

/**
 * 공격 1건에 연결된 탐지 알림 1개
 * srcIp·username 은 alert 자신의 값 (탐지 기준의 계정 구분용, 모르면 null)
 * control 은 알림을 낸 통제 (R14 — detection_link.control)
 */
public record DetectionLink(String ruleId, String technique, Instant alertTime,
                            MatchPath matchPath, double confidence, String srcIp, String username,
                            DetectionControl control) {

    public DetectionLink(String ruleId, String technique, Instant alertTime,
                         MatchPath matchPath, double confidence, String srcIp, String username) {
        this(ruleId, technique, alertTime, matchPath, confidence, srcIp, username, DetectionControl.APP_RULE);
    }

    public DetectionLink(String ruleId, String technique, Instant alertTime, MatchPath matchPath, double confidence) {
        this(ruleId, technique, alertTime, matchPath, confidence, null, null);
    }

    public static DetectionLink of(String ruleId, String technique, Instant alertTime, MatchPath matchPath) {
        return new DetectionLink(ruleId, technique, alertTime, matchPath, Confidence.of(matchPath).value());
    }

    public static DetectionLink of(AlertEvent alert, MatchPath matchPath) {
        return new DetectionLink(alert.ruleId(), alert.technique(), alert.alertTime(), matchPath,
                Confidence.of(matchPath).value(), alert.srcIp(), alert.username(), alert.control());
    }

    public boolean usable() {
        return new Confidence(confidence).usableForVerdict();
    }
}
