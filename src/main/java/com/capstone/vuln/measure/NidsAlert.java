package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * Wazuh 에 색인된 Suricata alert(rule.id 86601) 1건 (R14 a)
 * - alertTime: Wazuh timestamp (결정4), searchableTime: nullable
 * - flowId·txId: data.flow_id·data.tx_id — Wazuh 는 flow_id 를 실수 문자열로 저장한다. 정수가 아니면 null(연결 안 함)
 */
public record NidsAlert(int sid, Instant alertTime, Instant searchableTime, Long flowId, Long txId, String srcIp) {
}
