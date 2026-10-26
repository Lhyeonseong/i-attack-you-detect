package com.capstone.vuln.measure;

import java.util.List;

/**
 * 정상 요청 1건 × 통제 1개 판정 (validation.benign_result 1행, R18 a) — alerted = 판정용 알림 ≥ 1 (FP),
 * linkedRuleIds = 판정용 알림의 룰 ID(알림 1개당 1개), recordedRuleIds = 연결됐지만 판정에 안 쓰는 알림(TELEMETRY·MARKER 등)
 */
public record BenignResult(int seq, String control, List<String> linkedRuleIds, List<String> recordedRuleIds) {

    public boolean alerted() {
        return !linkedRuleIds.isEmpty();
    }

    public int alertCount() {
        return linkedRuleIds.size();
    }
}
