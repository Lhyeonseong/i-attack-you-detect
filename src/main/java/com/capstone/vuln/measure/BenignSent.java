package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * 정상 코퍼스 요청 1건의 전송 기록 (R17 c) — requestTarget = 보낸 path+query 원문(eve http.url 과 같은 형태),
 * appArgs = 앱 로그 http_request.args 형태, status = HTTP 상태(전송 실패 -1)
 */
public record BenignSent(int seq, String endpoint, String requestTarget, String appArgs,
                         Instant sentAt, Instant respondedAt, int status) {
}
