package com.capstone.vuln.measure;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Wazuh indexer(OpenSearch) 직접 질의 — measure 전용 최소 클라이언트(옆 모듈 재사용 금지).
 * op 창 [from, to] 로 timestamp(range, epoch_millis) 를 제한하고 커스텀 탐지룰 그룹(rule.groups,
 * 기본 vuln-webapp)으로 좁힌다 — rule.id prefix 는 Wazuh 내장 rule 1002 까지 끌어와 노이즈가 되므로
 * 명시 식별자인 그룹으로 거른다.
 *
 * <p>S4-4 (ADR-S4-01 v1.7 R14 a): {@link #forRuleId} 는 같은 창을 rule.id term(86601 = Suricata alert)으로 좁힌다.
 * 기존 그룹 질의는 그대로다(86601 은 vuln-webapp 그룹이 아니다).
 *
 * <p>TLS 는 {@link IndexerTls}: caFile 을 주면 인덱서 루트 CA 로 체인을 검증하고 호스트명 검증만 생략(127.0.0.1 접속),
 * 주지 않으면(null) 기존과 같은 trust-all(랩 전용). 어느 쪽이든 JVM 전역 속성·클라이언트 생성 순서와 무관하다(S4-5).
 * 접속 비밀번호만 env 로 주입받고 CRLF 를 trim 한다(.env 특이사항 — 안 하면 401).
 */
public class IndexerAlertSearchSource implements AlertSearchSource {

    private final HttpClient http;
    private final String searchUrl;
    private final String authHeader;
    /** term 필터 필드 — rule.groups(기존) 또는 rule.id(R14 a) */
    private final String filterField;
    private final String filterValue;

    public IndexerAlertSearchSource(String baseUrl, String indexPattern,
                                    String username, String password, String ruleGroups) {
        this(baseUrl, indexPattern, username, password, ruleGroups, null);
    }

    /** caFile: 인덱서 루트 CA(PEM) — null 이면 trust-all */
    public IndexerAlertSearchSource(String baseUrl, String indexPattern,
                                    String username, String password, String ruleGroups, Path caFile) {
        this(baseUrl, indexPattern, username, password, "rule.groups", ruleGroups, caFile);
    }

    /** R14 a: rule.id = ruleId 인 alert 만 (예: 86601 Suricata alert) */
    public static IndexerAlertSearchSource forRuleId(String baseUrl, String indexPattern,
                                                     String username, String password, String ruleId) {
        return forRuleId(baseUrl, indexPattern, username, password, ruleId, null);
    }

    public static IndexerAlertSearchSource forRuleId(String baseUrl, String indexPattern,
                                                     String username, String password, String ruleId, Path caFile) {
        return new IndexerAlertSearchSource(baseUrl, indexPattern, username, password, "rule.id", ruleId, caFile);
    }

    private IndexerAlertSearchSource(String baseUrl, String indexPattern, String username, String password,
                                     String filterField, String filterValue, Path caFile) {
        this.searchUrl = trimSlash(baseUrl) + "/" + indexPattern + "/_search";
        this.filterField = filterField;
        this.filterValue = filterValue;
        String user = username == null ? "" : username.strip();
        String pass = password == null ? "" : password.strip(); // .env CRLF 제거
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
        this.http = HttpClient.newBuilder()
                .sslContext(IndexerTls.context(caFile))
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @Override
    public String search(Instant fromInclusive, Instant toInclusive) {
        String body = body(fromInclusive.toEpochMilli(), toInclusive.toEpochMilli());
        HttpRequest request = HttpRequest.newBuilder(URI.create(searchUrl))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .header("Authorization", authHeader)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException("인덱서 alert 질의 실패: HTTP " + response.statusCode());
            }
            return response.body();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("인덱서 alert 질의 I/O 실패", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("인덱서 alert 질의 중단됨", e);
        }
    }

    /**
     * op 창 [fromMs, toMs] 를 timestamp(epoch_millis)로 제한하고 rule.groups term 으로 커스텀
     * 탐지룰만 거른다(내장 rule 1002 등 비-그룹 alert 제외). 순수 함수 — 단위테스트 대상.
     */
    static String searchBody(long fromMs, long toMs, String ruleGroups) {
        return """
                {"size":2000,"sort":[{"timestamp":{"order":"asc"}}],
                 "query":{"bool":{"filter":[
                   {"range":{"timestamp":{"gte":%d,"lte":%d,"format":"epoch_millis"}}},
                   {"term":{"rule.groups":"%s"}}
                 ]}}}""".formatted(fromMs, toMs, ruleGroups);
    }

    /**
     * R14 a: 같은 창 + rule.id term (Suricata alert 86601). track_total_hits — 받은 수와 비교해 검색 상한 초과를
     * 알아내기 위해 정확한 total 을 받는다(AlertIndexReader.readNids)
     */
    static String ruleIdSearchBody(long fromMs, long toMs, String ruleId) {
        return """
                {"size":2000,"track_total_hits":true,"sort":[{"timestamp":{"order":"asc"}}],
                 "query":{"bool":{"filter":[
                   {"range":{"timestamp":{"gte":%d,"lte":%d,"format":"epoch_millis"}}},
                   {"term":{"rule.id":"%s"}}
                 ]}}}""".formatted(fromMs, toMs, ruleId);
    }

    private String body(long fromMs, long toMs) {
        return "rule.id".equals(filterField) ? ruleIdSearchBody(fromMs, toMs, filterValue)
                : searchBody(fromMs, toMs, filterValue);
    }

    private static String trimSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
