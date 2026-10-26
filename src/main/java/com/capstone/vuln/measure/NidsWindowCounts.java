package com.capstone.vuln.measure;

/**
 * op 창 1개의 NIDS 집계 (validation.nids_window_stat 1행)
 * - nidsAlerts: 창 안 86601 alert 수, orphanAlerts: eve http 와 (flow_id, tx_id) 로 연결되지 않은 수(R14 b)
 * - analytic/telemetry/marker/undecided/unclassified: sid 분류별 alert 수(R14 d), analyticLinked: 시도까지 연결된 ANALYTIC 수
 * - httpEvents: 창 안 eve http 수, httpAttributed: 시도에 연결된 http 수(R14 c)
 */
public record NidsWindowCounts(int nidsAlerts, int orphanAlerts, int analyticAlerts, int analyticLinked,
                               int telemetryAlerts, int markerAlerts, int undecidedAlerts, int unclassifiedAlerts,
                               int httpEvents, int httpAttributed) {
}
