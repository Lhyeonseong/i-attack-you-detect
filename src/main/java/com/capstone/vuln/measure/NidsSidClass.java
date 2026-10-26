package com.capstone.vuln.measure;

/**
 * Suricata sid 분류 (ADR-S4-01 v1.7 R14 d, validation.nids_sid_class.class)
 * - ANALYTIC: 공격 패턴 또는 임계치 — 탐지·verdict·M13 에 반영
 * - TELEMETRY: 엔드포인트 요청 자체 매칭(정상 요청에도 걸림) — 수만 기록
 * - MARKER: Caldera UA·X-Caldera 헤더 — technique-under-test 아님, B안으로 제외
 * - UNDECIDED: 판단 보류 — 링크 제외
 */
public enum NidsSidClass {
    ANALYTIC,
    TELEMETRY,
    MARKER,
    UNDECIDED
}
