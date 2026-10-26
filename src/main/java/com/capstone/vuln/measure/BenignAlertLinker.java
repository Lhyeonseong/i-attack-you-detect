package com.capstone.vuln.measure;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 정상 요청 ↔ 알림 연결과 요청 × 통제 판정 (ADR-S4-01 v1.8 R18 a~c·g). 순수 로직.
 *
 * <p>통제 적용(R18 b): APP_RULE = SQLI·PATH_TRAVERSAL·SSRF 엔드포인트, NIDS = ANALYTIC sid 가 있는 엔드포인트,
 * BACKEND_CORR = login(BRUTE_FORCE) 요청(웹 엔드포인트에는 결과 행 없음). 대조되지 않은 요청(rid 없음)은 결과 행이 없다(R10 이 막는다).
 * <ul>
 *   <li>APP_RULE: alert data.rid = 요청 rid → 판정용 알림. rid 가 없거나 어느 요청과도 안 맞으면 미연결 NO_MATCH</li>
 *   <li>NIDS: data.http.url = 요청 대상 ∧ eve 시각 ∈ [전송 − 허용오차, 응답 + 허용오차] ∧ Wazuh 시각 ≤ 응답 + 관찰창.
 *       후보 1개면 연결 — ANALYTIC 이면 판정용, 그 밖의 분류는 기록만. 후보 0·2개 이상이면 미연결(NO_CANDIDATE·AMBIGUOUS).
 *       배경(src·dest 가 fe80::/10·ff00::/8)은 미연결 기록에서도 뺀다. login 은 모든 요청의 url 이 같으므로(/api/auth/login)
 *       단일 후보는 요청 시각 창이 겹치지 않아야 성립한다(ExternalSendIngest §I)</li>
 *   <li>BACKEND_CORR(login, R18 j v2.0): alert data.rid = 요청 rid 로 연결(APP_RULE 과 같은 rid 대조). 100231(실패 10회)·
 *       100233(반복 실패 후 성공)이 링크되면 판정용(FP). 100230(실패 단건)·100232(성공 단건)은 기록만(recorded).
 *       CorrelationEngine·VerdictEngine 을 쓰지 않고 상관 룰 alert 유무로만 판정한다(B안: 관제 독립, gtOutcome 미사용)</li>
 * </ul>
 */
public class BenignAlertLinker {

    public static final Duration EVENT_TOLERANCE = Duration.ofMillis(50);

    /** R18 j: login 상관 통제의 판정용 상관 룰 — 시퀀스 성립 시 1회 뜨는 룰(FP). 그 밖(100230·100232 등)은 기록만 */
    private static final java.util.Set<String> BACKEND_CORR_SEQUENCE = java.util.Set.of("100231", "100233");

    public record Result(List<BenignResult> results, List<BenignUnlinkedAlert> unlinked) {
    }

    private final NidsSidCatalog catalog;
    private final Duration observation;

    public BenignAlertLinker(NidsSidCatalog catalog, Duration observation) {
        this.catalog = catalog;
        this.observation = observation;
    }

    public Result link(List<BenignSent> sent, Map<Integer, String> ridBySeq, List<BenignAppAlert> appAlerts,
                       List<BenignNidsAlert> nidsAlerts) {
        Map<String, Integer> seqByRid = new HashMap<>();
        ridBySeq.forEach((seq, rid) -> seqByRid.put(rid, seq));
        Map<Integer, List<String>> app = new HashMap<>();
        Map<Integer, List<String>> nids = new HashMap<>();
        Map<Integer, List<String>> nidsRecorded = new HashMap<>();
        List<BenignUnlinkedAlert> unlinked = new ArrayList<>();

        for (BenignAppAlert a : appAlerts) {
            Integer seq = a.rid() == null ? null : seqByRid.get(a.rid());
            if (seq == null) {
                unlinked.add(new BenignUnlinkedAlert("APP_RULE", a.ruleId(), a.alertTime(), "NO_MATCH"));
            } else {
                app.computeIfAbsent(seq, k -> new ArrayList<>()).add(a.ruleId());
            }
        }

        for (BenignNidsAlert a : nidsAlerts) {
            if (background(a.srcIp()) || background(a.destIp())) {
                continue;
            }
            List<BenignSent> candidates = sent.stream()
                    .filter(s -> ridBySeq.containsKey(s.seq()))
                    .filter(s -> s.requestTarget().equals(a.url()))
                    .filter(s -> a.eventTime() != null
                            && !a.eventTime().isBefore(s.sentAt().minus(EVENT_TOLERANCE))
                            && !a.eventTime().isAfter(s.respondedAt().plus(EVENT_TOLERANCE)))
                    .filter(s -> !a.alertTime().isAfter(s.respondedAt().plus(observation)))
                    .toList();
            String sid = String.valueOf(a.sid());
            if (candidates.size() != 1) {
                unlinked.add(new BenignUnlinkedAlert("NIDS", sid, a.alertTime(),
                        candidates.isEmpty() ? "NO_CANDIDATE" : "AMBIGUOUS"));
                continue;
            }
            int seq = candidates.get(0).seq();
            boolean analytic = catalog.entry(a.sid()).map(e -> e.sidClass() == NidsSidClass.ANALYTIC).orElse(false);
            (analytic ? nids : nidsRecorded).computeIfAbsent(seq, k -> new ArrayList<>()).add(sid);
        }

        List<BenignResult> results = new ArrayList<>();
        for (BenignSent s : sent) {
            if (!ridBySeq.containsKey(s.seq())) {
                continue;
            }
            String scenario = ScenarioMapping.scenarioFor(s.endpoint());
            if (appRuleApplies(scenario)) {
                results.add(new BenignResult(s.seq(), "APP_RULE", app.getOrDefault(s.seq(), List.of()), List.of()));
            }
            if (nidsApplies(scenario)) {
                results.add(new BenignResult(s.seq(), "NIDS", nids.getOrDefault(s.seq(), List.of()),
                        nidsRecorded.getOrDefault(s.seq(), List.of())));
            }
            if (backendCorrApplies(scenario)) {
                List<String> appIds = app.getOrDefault(s.seq(), List.of());
                List<String> fp = appIds.stream().filter(BACKEND_CORR_SEQUENCE::contains).toList();
                List<String> recorded = appIds.stream().filter(id -> !BACKEND_CORR_SEQUENCE.contains(id)).toList();
                results.add(new BenignResult(s.seq(), "BACKEND_CORR", fp, recorded));
            }
        }
        return new Result(results, unlinked);
    }

    private static boolean appRuleApplies(String scenario) {
        return "SQLI".equals(scenario) || "PATH_TRAVERSAL".equals(scenario) || "SSRF".equals(scenario);
    }

    /** R18 b·j: BACKEND_CORR 는 login(BRUTE_FORCE) 요청에만 적용 — 웹 엔드포인트는 결과 행 없음(뷰가 NO_RULE) */
    private static boolean backendCorrApplies(String scenario) {
        return "BRUTE_FORCE".equals(scenario);
    }

    private boolean nidsApplies(String scenario) {
        return catalog.entries().stream()
                .anyMatch(e -> e.sidClass() == NidsSidClass.ANALYTIC && scenario.equals(e.scenario()));
    }

    /** IPv6 link-local(fe80::/10)·multicast(ff00::/8) */
    static boolean background(String ip) {
        if (ip == null || !ip.contains(":")) {
            return false;
        }
        try {
            byte[] b = InetAddress.getByName(ip).getAddress();
            return b.length == 16 && ((b[0] & 0xff) == 0xff || ((b[0] & 0xff) == 0xfe && (b[1] & 0xc0) == 0x80));
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
