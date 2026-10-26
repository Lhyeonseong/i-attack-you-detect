package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * Suricata alert(Wazuh 86601) 1건 (R18 c) — alertTime = Wazuh timestamp, eventTime = data.timestamp(eve 시각),
 * url = data.http.url(요청 대상 원문)
 */
public record BenignNidsAlert(int sid, Instant alertTime, Instant eventTime, String url, String srcIp, String destIp) {
}
