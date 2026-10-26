package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * eve.json http 이벤트 1건 (R14 b·c) — url 은 eve 원문(인코딩된 path+query), userAgent 는 http_user_agent
 */
public record EveHttp(long flowId, long txId, Instant time, String url, String userAgent,
                      String srcIp, String destIp, Integer destPort) {
}
