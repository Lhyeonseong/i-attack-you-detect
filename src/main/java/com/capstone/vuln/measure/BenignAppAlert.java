package com.capstone.vuln.measure;

import java.time.Instant;

/** Wazuh 앱 로그 룰 alert(vuln-webapp 그룹) 1건 — rid = data.rid (S4-5 C2), 없으면 null */
public record BenignAppAlert(String ruleId, String rid, Instant alertTime) {
}
