package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.Correlation;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.DetectionControl;
import com.capstone.vuln.correlation.DetectionLink;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import com.capstone.vuln.correlation.MatchPath;
import com.capstone.vuln.correlation.OperationLink;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * T1~T5 — ADR-S4-01 v1.7 R14 b·c·d: Suricata alert(86601) → eve http (flow_id, tx_id) → 시도.
 * 기대값은 픽스처에서 손으로 센 값만 쓴다.
 */
class NidsCorrelatorTest {

    private static final Instant T0 = Instant.parse("2026-10-21T10:00:00Z");
    private static final String PAW = "eiwwvn";
    private static final String IP = "172.20.0.1";
    private static final String APP = "172.20.0.3";
    private static final String SQLI_AB = "e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c";
    private static final String PT_AB = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String BF_AB = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";
    private static final String SSRF_AB = "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";

    private final List<AttackEvent> attacks = new ArrayList<>();
    private final Map<String, String> args = new HashMap<>();
    private final List<EveHttp> http = new ArrayList<>();
    private final List<NidsAlert> alerts = new ArrayList<>();
    private final List<OperationLink> links = new ArrayList<>();

    private final NidsCorrelator correlator = new NidsCorrelator(NidsSidCatalog.V1_7);

    private static Instant at(long ms) {
        return T0.plusMillis(ms);
    }

    private void link(String op, String ability, long decideMs, long finishMs) {
        links.add(new OperationLink(op, PAW, ability, at(decideMs), at(finishMs)));
    }

    private void event(String rid, String ability, String scenario, String technique, long ms, String path,
                       String requestArgs, GroundTruthOutcome gt) {
        String username = AlertEvent.usernameFromArgs(requestArgs);
        attacks.add(new AttackEvent(new CorrelationKey(PAW, ability, rid), scenario, technique, at(ms), IP, path,
                username, gt));
        args.put(rid, requestArgs);
    }

    private void http(long flowId, long txId, long ms, String url, String technique, String ability) {
        http.add(new EveHttp(flowId, txId, at(ms), url, "Caldera/" + PAW + "/" + technique + "/" + ability,
                IP, APP, 8080));
    }

    private void alert(int sid, long ms, Long flowId, Long txId) {
        alerts.add(new NidsAlert(sid, at(ms), null, flowId, txId, IP));
    }

    private NidsCorrelator.Result run() {
        return correlator.correlate(attacks, args, alerts, http, links);
    }

    // ---- T1 ----

    /**
     * 같은 paw 20 op, 각 op SQLi 1건 (URL·ability 동일). op 창 [12i s, 12i+10 s] (+1s 포함), 시도 = 12i+0.5 s,
     * http = 시도 + 20 ms. 예외: op 5 의 http 는 70.8 s — 시각만 보면 op 6 시도(72.5 s)가 더 가깝지만 op 5 창 안이므로 op 5 시도.
     */
    @Test
    void t1SamePawTwentyOperationsEachHttpLinksToItsOwnOperationAttempt() {
        for (int i = 0; i < 20; i++) {
            long decide = 12_000L * i;
            link("op-" + i, SQLI_AB, decide, decide + 10_000);
            long attempt = i == 6 ? 72_500 : decide + 500;
            event("sqli-" + i, SQLI_AB, "SQLI", "T1190", attempt, "/api/products/search", "keyword='",
                    GroundTruthOutcome.SUCCEEDED);
            long httpAt = i == 5 ? 70_800 : attempt + 20;
            http(5000 + i, 0, httpAt, "/api/products/search?keyword=%27", "T1190", SQLI_AB);
        }
        // ability 가 다른 http (PT ability 로 SQLi URL) — 어느 시도에도 연결되지 않는다
        http(9999, 0, 520, "/api/products/search?keyword=%27", "T1190", PT_AB);
        alert(1000013, 72_000, 5005L, 0L); // ANALYTIC — op 5 의 http

        NidsCorrelator.Result r = run();

        assertEquals(20, r.httpByRid().size());
        for (int i = 0; i < 20; i++) {
            assertEquals(1, r.httpByRid().get("sqli-" + i), "sqli-" + i);
        }
        assertEquals(21, r.counts().httpEvents());
        assertEquals(20, r.counts().httpAttributed());
        assertEquals(1, r.alerts().size());
        AlertEvent a = r.alerts().get(0);
        assertEquals("sqli-5", a.rid());
        assertEquals("1000013", a.ruleId());
        assertEquals("T1190", a.technique());
        assertEquals(DetectionControl.NIDS, a.control());
        assertEquals(at(72_000), a.alertTime());
    }

    // ---- T2 ----

    /** PT 한 op 3요청은 URL 로 서로 다른 시도에 연결된다(시각은 일부러 섞음). 후보 0 이면 링크 없음 */
    @Test
    void t2PathTraversalRequestsLinkByUrlAndNoCandidateMeansNoLink() {
        link("op-pt", PT_AB, 0, 10_000);
        event("pt-passwd", PT_AB, "PATH_TRAVERSAL", "T1190", 1_000, "/api/files/download",
                "filename=../../../../etc/passwd", GroundTruthOutcome.SUCCEEDED);
        event("pt-hostname", PT_AB, "PATH_TRAVERSAL", "T1190", 1_100, "/api/files/download",
                "filename=../../../../etc/hostname", GroundTruthOutcome.SUCCEEDED);
        event("pt-hosts", PT_AB, "PATH_TRAVERSAL", "T1190", 1_200, "/api/files/download",
                "filename=../../../../etc/hosts", GroundTruthOutcome.SUCCEEDED);
        // hostname http 를 passwd 시도에 가장 가까운 시각에 둔다 — URL 이 결정해야 한다
        http(1, 0, 1_195, "/api/files/download?filename=../../../../etc/passwd", "T1190", PT_AB);
        http(2, 0, 1_002, "/api/files/download?filename=../../../../etc/hostname", "T1190", PT_AB);
        http(3, 0, 1_210, "/api/files/download?filename=../../../../etc/hosts", "T1190", PT_AB);
        http(4, 0, 1_300, "/api/files/download?filename=../../../../etc/shadow", "T1190", PT_AB); // 시도 없음
        alert(1000020, 2_000, 2L, 0L);
        alert(1000020, 2_100, 4L, 0L); // http 는 있으나 시도 후보 0 → 링크 없음

        NidsCorrelator.Result r = run();

        assertEquals(Map.of("pt-passwd", 1, "pt-hostname", 1, "pt-hosts", 1), r.httpByRid());
        assertEquals(1, r.alerts().size());
        assertEquals("pt-hostname", r.alerts().get(0).rid());
        assertEquals(2, r.counts().analyticAlerts());
        assertEquals(1, r.counts().analyticLinked());
        assertEquals(0, r.counts().orphanAlerts());
    }

    /** eve query 는 정확히 1회 디코딩(서버와 같음): 1회 인코딩은 연결, 2중 인코딩은 연결 안 됨 */
    @Test
    void t2bQueryIsDecodedExactlyOnce() {
        link("op-ssrf", SSRF_AB, 0, 10_000);
        event("ssrf-md", SSRF_AB, "SSRF", "T1190", 1_000, "/api/preview",
                "url=http://169.254.169.254/latest/meta-data/", GroundTruthOutcome.SUCCEEDED);
        http(1, 0, 1_010, "/api/preview?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "T1190", SSRF_AB);
        http(2, 0, 1_020, "/api/preview?url=http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F",
                "T1190", SSRF_AB);

        NidsCorrelator.Result r = run();

        assertEquals(Map.of("ssrf-md", 1), r.httpByRid());
        assertEquals(1, r.counts().httpAttributed());
    }


    /**
     * 같은 SSRF args 를 매우 짧은 간격으로 2번 실행해도,
     * 각 eve http 는 자신의 시점보다 미래의 시도가 아니라
     * 실제로 이미 발생한 각 시도에 1건씩 귀속되어야 한다.
     */
    @Test
    void t2cBackToBackSameSsrfRequestsDoNotCollapseIntoLaterAttempt() {
        link("op-ssrf-close", SSRF_AB, 0, 10_000);

        String requestArgs = "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role";
        String encodedUrl = "/api/preview?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2Fmock-iam-role";

        event("ssrf-1", SSRF_AB, "SSRF", "T1190", 1_000, "/api/preview",
                requestArgs, GroundTruthOutcome.SUCCEEDED);
        event("ssrf-2", SSRF_AB, "SSRF", "T1190", 1_279, "/api/preview",
                requestArgs, GroundTruthOutcome.SUCCEEDED);

        // 입력 순서가 뒤집혀도 event timestamp 기준으로 동일하게 귀속되어야 한다.
        http(102, 0, 1_287, encodedUrl, "T1190", SSRF_AB);
        http(101, 0, 1_233, encodedUrl, "T1190", SSRF_AB);

        alert(1000060, 1_240, 101L, 0L);
        alert(1000060, 1_294, 102L, 0L);

        NidsCorrelator.Result r = run();

        assertEquals(Map.of("ssrf-1", 1, "ssrf-2", 1), r.httpByRid());
        assertEquals(2, r.alerts().size());
        assertEquals("ssrf-1", r.alerts().get(0).rid());
        assertEquals("ssrf-2", r.alerts().get(1).rid());
    }

    // ---- T3 ----

    /** alert ↔ http 는 (flow_id, tx_id) 로만 — 같은 flow 다른 tx 구분, 키 불일치·정수 아닌 flow_id 는 orphan */
    @Test
    void t3AlertJoinsHttpByFlowAndTxAndMismatchIsOrphan() {
        link("op-pt", PT_AB, 0, 10_000);
        event("pt-passwd", PT_AB, "PATH_TRAVERSAL", "T1190", 1_000, "/api/files/download",
                "filename=../../../../etc/passwd", GroundTruthOutcome.SUCCEEDED);
        event("pt-hosts", PT_AB, "PATH_TRAVERSAL", "T1190", 1_200, "/api/files/download",
                "filename=../../../../etc/hosts", GroundTruthOutcome.SUCCEEDED);
        http(77, 0, 1_010, "/api/files/download?filename=../../../../etc/passwd", "T1190", PT_AB);
        http(77, 1, 1_210, "/api/files/download?filename=../../../../etc/hosts", "T1190", PT_AB);
        alert(1000020, 2_000, 77L, 1L);   // → tx 1 = pt-hosts
        alert(1000020, 2_000, 78L, 0L);   // flow 불일치 → orphan
        alert(1000020, 2_000, null, 0L);  // flow_id 정수 아님(파싱 null) → orphan

        NidsCorrelator.Result r = run();

        assertEquals(1, r.alerts().size());
        assertEquals("pt-hosts", r.alerts().get(0).rid());
        assertEquals(3, r.counts().nidsAlerts());
        assertEquals(2, r.counts().orphanAlerts());
        assertEquals(1, r.counts().analyticLinked());
    }

    // ---- T4 ----

    /** MARKER·TELEMETRY·UNDECIDED·분류표 밖 sid 는 링크가 되지 않는다 — ANALYTIC 1건만 control=NIDS 링크 */
    @Test
    void t4OnlyAnalyticSidBecomesNidsLink() {
        link("op-pt", PT_AB, 0, 10_000);
        event("pt-passwd", PT_AB, "PATH_TRAVERSAL", "T1190", 1_000, "/api/files/download",
                "filename=../../../../etc/passwd", GroundTruthOutcome.SUCCEEDED);
        http(10, 0, 1_010, "/api/files/download?filename=../../../../etc/passwd", "T1190", PT_AB);
        alert(1000001, 2_000, 10L, 0L); // MARKER
        alert(1000030, 2_000, 10L, 0L); // TELEMETRY
        alert(1000018, 2_000, 10L, 0L); // UNDECIDED
        alert(1000050, 2_000, 10L, 0L); // 분류표 밖 (XSS)
        alert(1000020, 2_000, 10L, 0L); // ANALYTIC

        NidsCorrelator.Result r = run();

        assertEquals(1, r.alerts().size());
        assertEquals("1000020", r.alerts().get(0).ruleId());
        NidsWindowCounts c = r.counts();
        assertEquals(5, c.nidsAlerts());
        assertEquals(1, c.markerAlerts());
        assertEquals(1, c.telemetryAlerts());
        assertEquals(1, c.undecidedAlerts());
        assertEquals(1, c.unclassifiedAlerts());
        assertEquals(1, c.analyticAlerts());
        assertEquals(1, c.analyticLinked());

        List<Correlation> correlations = new CorrelationEngine().correlate(attacks, r.alerts());
        assertEquals(1, correlations.size());
        List<DetectionLink> l = correlations.get(0).getLinks();
        assertEquals(1, l.size());
        assertEquals(DetectionControl.NIDS, l.get(0).control());
        assertEquals(MatchPath.UA_FALLBACK, l.get(0).matchPath());
        assertEquals(0.7, l.get(0).confidence(), 0.0);
        assertEquals("1000020", l.get(0).ruleId());
    }

    // ---- T5 ----

    /** BF 시퀀스 13요청(query 없음 → path + 창 + ability, 최근접) 중 ANALYTIC 1000031 1건이 BF 시도 1건에 연결 */
    @Test
    void t5BruteForceAnalyticAlertLinksToTheSingleSequenceAttempt() {
        link("op-bf", BF_AB, 0, 10_000);
        for (int i = 0; i < 13; i++) {
            event("bf-" + i, BF_AB, "BRUTE_FORCE", "T1110", 1_000 + 100L * i, "/api/auth/login", "username=user1",
                    i < 12 ? GroundTruthOutcome.FAILED : GroundTruthOutcome.SUCCEEDED);
            http(100 + i, 0, 1_005 + 100L * i, "/api/auth/login", "T1110", BF_AB);
        }
        alert(1000030, 3_000, 100L, 0L); // TELEMETRY — 링크 아님
        alert(1000031, 3_000, 109L, 0L); // ANALYTIC — 10번째 요청

        NidsCorrelator.Result r = run();

        assertEquals(13, r.httpByRid().size());
        assertEquals(1, r.alerts().size());
        assertEquals("bf-9", r.alerts().get(0).rid());
        assertEquals("T1110", r.alerts().get(0).technique());

        List<Correlation> correlations = new CorrelationEngine().correlate(attacks, r.alerts());
        assertEquals(1, correlations.size(), "BF 시퀀스 = 시도 1건");
        assertEquals(13, correlations.get(0).getEventRids().size());
        assertEquals(1, correlations.get(0).getLinks().size());
        assertEquals(DetectionControl.NIDS, correlations.get(0).getLinks().get(0).control());
    }

    /** UA 가 Caldera 형식이 아니거나 Caldera 링크가 없으면(조회 실패) 연결하지 않는다 */
    @Test
    void httpWithoutCalderaUaOrWithoutOperationLinkIsNotAttributed() {
        event("sqli-0", SQLI_AB, "SQLI", "T1190", 1_000, "/api/products/search", "keyword='",
                GroundTruthOutcome.SUCCEEDED);
        http.add(new EveHttp(1, 0, at(1_010), "/api/products/search?keyword=%27", "curl/8.5.0", IP, APP, 8080));
        http(2, 0, 1_020, "/api/products/search?keyword=%27", "T1190", SQLI_AB); // links 비어 있음

        NidsCorrelator.Result r = run();

        assertTrue(r.httpByRid().isEmpty());
        assertEquals(0, r.counts().httpAttributed());
    }
}
