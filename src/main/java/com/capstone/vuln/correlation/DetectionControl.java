package com.capstone.vuln.correlation;

/**
 * 탐지 알림을 낸 통제 (ADR-S4-01 v1.7 R14·R16, detection_link.control)
 * - APP_RULE: Wazuh 앱 로그 룰(vuln-webapp 그룹) — R14 이전 링크는 전부 이것
 * - NIDS: Suricata alert(Wazuh 86601) — eve http 를 거쳐 시도에 연결(R14 b·c), ANALYTIC sid 만
 * BACKEND_CORR(VerdictEngine BF 시퀀스)는 링크가 아니라 verdict 판정이라 여기 없다.
 */
public enum DetectionControl {
    APP_RULE,
    NIDS
}
