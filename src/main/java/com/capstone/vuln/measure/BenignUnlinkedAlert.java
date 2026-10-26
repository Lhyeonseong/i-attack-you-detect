package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * 측정 창 안 미연결 알림 (R18 g, 기록만) — sensor APP_RULE·NIDS,
 * reason: NO_MATCH(APP_RULE rid 불일치·없음), NO_CANDIDATE·AMBIGUOUS(NIDS 후보 0·2개 이상)
 */
public record BenignUnlinkedAlert(String sensor, String ruleId, Instant alertTime, String reason) {
}
