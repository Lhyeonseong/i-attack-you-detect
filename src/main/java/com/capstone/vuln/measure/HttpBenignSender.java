package com.capstone.vuln.measure;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * target-web 으로 정상 GET 1건 (R17 a) — 브라우저형 UA·Accept 만 보내고 Caldera 헤더는 보내지 않는다.
 * 응답 본문은 버린다(저장 금지 원칙). preview 의 외부 fetch(최대 3 s + 3 s)보다 긴 요청 타임아웃을 쓴다.
 */
public class HttpBenignSender implements BenignSender {

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final String baseUrl;
    private final Duration requestTimeout;

    public HttpBenignSender(String baseUrl, Duration requestTimeout) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.requestTimeout = requestTimeout;
    }

    @Override
    public int send(String requestTarget) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + requestTarget))
                .timeout(requestTimeout)
                .header("User-Agent", USER_AGENT)
                .header("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
                .GET()
                .build();
        return http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
