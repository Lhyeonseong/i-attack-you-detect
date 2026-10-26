package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.OperationLink;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Suricata alert(86601) → eve http → 시도 (ADR-S4-01 v1.7 R14 b·c·d). 순수 로직 — 판정은 엔진이 한다.
 *
 * <p>R14 c http↔시도: UA(Caldera/paw/technique/ability)의 paw·ability 가 같고, http 시각과 시도 시각이 같은 Caldera
 * 링크 창(OperationLink.covers — OperationResolver 와 같은 창)에 들고, URL 이 일치하는 시도. path 는 그대로,
 * eve query 는 정확히 1회 URL 디코딩(서버와 같은 1회)해 앱 http_request.args 와 비교, query 가 없으면 path·창·ability 만.
 * 후보 여럿이면 HTTP 시각 이전에 발생한 시도를 우선하고, 그 안에서 시각 최근접
 * (같으면 이른 시도, 그다음 rid 순). 이전 후보가 없으면 미래 후보 중 최근접, 0 이면 연결 안 함.
 *
 * <p>R14 b alert↔http: (flow_id, tx_id) 일치만. 연결 http 가 없는 alert 는 orphan 으로 센다(sid 분류와 무관).
 * R14 d: ANALYTIC sid 만 AlertEvent(control=NIDS)로 낸다. 나머지는 분류별 수만 센다.
 */
public class NidsCorrelator {

    /** alerts: 엔진에 넘길 NIDS AlertEvent, httpByRid: 시도 이벤트 rid → 연결된 eve http 수(R15), counts: 창 집계 */
    public record Result(List<AlertEvent> alerts, Map<String, Integer> httpByRid, NidsWindowCounts counts) {
    }

    private static final Pattern CALDERA_UA = Pattern.compile("^Caldera/([^/]+)/([^/]+)/([^/]+)$");

    private record HttpKey(long flowId, long txId) {
    }

    private final NidsSidCatalog catalog;

    public NidsCorrelator(NidsSidCatalog catalog) {
        this.catalog = catalog;
    }

    public Result correlate(List<AttackEvent> attacks, Map<String, String> argsByRid, List<NidsAlert> alerts,
                            List<EveHttp> http, List<OperationLink> links) {
        Map<HttpKey, AttackEvent> attemptByHttp = new HashMap<>();
        Map<HttpKey, EveHttp> httpByKey = new HashMap<>();
        Map<String, Integer> httpByRid = new LinkedHashMap<>();
        int attributed = 0;
        for (EveHttp h : http) {
            HttpKey key = new HttpKey(h.flowId(), h.txId());
            if (httpByKey.putIfAbsent(key, h) != null) {
                continue; // 같은 (flow_id, tx_id) 는 한 번만
            }
            AttackEvent attempt = attribute(h, attacks, argsByRid, links);
            if (attempt != null) {
                attemptByHttp.put(key, attempt);
                httpByRid.merge(attempt.key().rid(), 1, Integer::sum);
                attributed++;
            }
        }

        List<AlertEvent> out = new ArrayList<>();
        int orphan = 0, analytic = 0, linked = 0, telemetry = 0, marker = 0, undecided = 0, unclassified = 0;
        for (NidsAlert a : alerts) {
            Optional<NidsSidCatalog.Entry> entry = catalog.entry(a.sid());
            NidsSidClass sidClass = entry.map(NidsSidCatalog.Entry::sidClass).orElse(null);
            if (sidClass == null) {
                unclassified++;
            } else {
                switch (sidClass) {
                    case ANALYTIC -> analytic++;
                    case TELEMETRY -> telemetry++;
                    case MARKER -> marker++;
                    case UNDECIDED -> undecided++;
                }
            }
            HttpKey key = a.flowId() == null || a.txId() == null ? null : new HttpKey(a.flowId(), a.txId());
            if (key == null || !httpByKey.containsKey(key)) {
                orphan++;
                continue;
            }
            if (sidClass != NidsSidClass.ANALYTIC) {
                continue;
            }
            AttackEvent attempt = attemptByHttp.get(key);
            if (attempt == null) {
                continue; // http 는 있으나 시도 후보 0
            }
            out.add(AlertEvent.nids(String.valueOf(a.sid()), attempt.techniqueId(), a.alertTime(), a.searchableTime(),
                    attempt.key().rid(), a.srcIp(), attempt.endpoint()));
            linked++;
        }
        NidsWindowCounts counts = new NidsWindowCounts(alerts.size(), orphan, analytic, linked, telemetry, marker,
                undecided, unclassified, httpByKey.size(), attributed);
        return new Result(List.copyOf(out), httpByRid, counts);
    }

    /** R14 c — 연결할 시도 1건, 없으면 null */
    private static AttackEvent attribute(EveHttp h, List<AttackEvent> attacks, Map<String, String> argsByRid,
                                         List<OperationLink> links) {
        if (h.userAgent() == null || h.url() == null) {
            return null;
        }
        Matcher ua = CALDERA_UA.matcher(h.userAgent());
        if (!ua.matches()) {
            return null;
        }
        String paw = ua.group(1);
        String ability = ua.group(3);
        int q = h.url().indexOf('?');
        String path = q < 0 ? h.url() : h.url().substring(0, q);
        String query = q < 0 ? null : h.url().substring(q + 1);
        String decodedQuery;
        try {
            decodedQuery = query == null || query.isEmpty() ? null : URLDecoder.decode(query, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null; // 잘못된 % 인코딩 — 서버도 같은 값으로 읽지 못한다
        }

        List<OperationLink> windows = links.stream()
                .filter(l -> paw.equals(l.paw()) && ability.equals(l.abilityId()) && l.covers(h.time()))
                .toList();
        if (windows.isEmpty()) {
            return null;
        }
        return attacks.stream()
                .filter(e -> e.key().rid() != null)
                .filter(e -> paw.equals(e.key().agentPaw()) && ability.equals(e.key().abilityId()))
                .filter(e -> path.equals(e.endpoint()))
                .filter(e -> windows.stream().anyMatch(l -> l.covers(e.attackTime())))
                .filter(e -> decodedQuery == null || decodedQuery.equals(argsByRid.get(e.key().rid())))
                .min(Comparator.comparing((AttackEvent e) -> e.attackTime().isAfter(h.time()))
                        .thenComparing(e -> Duration.between(e.attackTime(), h.time()).abs())
                        .thenComparing(AttackEvent::attackTime)
                        .thenComparing(e -> Objects.requireNonNull(e.key().rid())))
                .orElse(null);
    }
}
