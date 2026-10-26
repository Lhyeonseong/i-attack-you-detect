package com.capstone.vuln.correlation;

/**
 * 텔레메트리 센서 (ADR-S4-01 v1.7 R15, telemetry_observation.sensor)
 * - APP_LOG: 앱 OCSF 로그 — 시도 원천이라 VALID run 에서 구조적으로 1 (해석 지표 아님)
 * - NIDS: Suricata eve http 이벤트 (R14 c 로 시도에 연결된 것)
 */
public enum TelemetrySensor {
    APP_LOG,
    NIDS
}
