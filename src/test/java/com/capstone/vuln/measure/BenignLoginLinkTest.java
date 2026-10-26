package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R18 j (v2.0) login 오탐 판정 — BenignAlertLinker 의 BRUTE_FORCE 분기. 순수 로직.
 * BACKEND_CORR 는 요청 rid 로 100231/100233 연결 시 FP, 100230/100232 는 기록만. login NIDS 는 1000031/1000032(url+시각창 단일 후보).
 * APP_RULE 행은 login 에 만들지 않는다. CorrelationEngine·VerdictEngine 미사용.
 */
class BenignLoginLinkTest {

    private static final Instant T0 = Instant.parse("2026-10-22T05:00:00Z");
    private static final String LOGIN = "/api/auth/login";

    /** login 요청 n 건 — url 은 모두 /api/auth/login(POST, 쿼리 없음), 500 ms 간격(§I 단일 후보 충족), 40 ms 응답 */
    private static List<BenignSent> logins(int n) {
        return java.util.stream.IntStream.rangeClosed(1, n)
                .mapToObj(s -> new BenignSent(s, LOGIN, LOGIN, "username=user1",
                        T0.plusMillis(500L * (s - 1)), T0.plusMillis(500L * (s - 1) + 40), s == 2 ? 401 : 200))
                .toList();
    }

    private static Map<Integer, String> rids(int n) {
        Map<Integer, String> m = new HashMap<>();
        for (int s = 1; s <= n; s++) {
            m.put(s, "r" + s);
        }
        return m;
    }

    private static BenignAppAlert app(String ruleId, String rid, long ms) {
        return new BenignAppAlert(ruleId, rid, T0.plusMillis(ms));
    }

    private static BenignNidsAlert nids(int sid, int seq, long eventMs, long alertMs) {
        return new BenignNidsAlert(sid, T0.plusMillis(alertMs), T0.plusMillis(eventMs), LOGIN, "127.0.0.1", "172.20.0.3");
    }

    private static Map<String, BenignResult> link(List<BenignSent> sent, Map<Integer, String> rids,
                                                  List<BenignAppAlert> app, List<BenignNidsAlert> nids) {
        BenignAlertLinker.Result r = new BenignAlertLinker(NidsSidCatalog.V1_7, Duration.ofSeconds(30))
                .link(sent, rids, app, nids);
        Map<String, BenignResult> by = new HashMap<>();
        r.results().forEach(x -> by.put(x.seq() + ":" + x.control(), x));
        return by;
    }

    /** 정상 로그인: 100230(401 단건)·100232(200 단건)만 뜨고 100231/100233 없음 → BACKEND_CORR FP 0, 기록만. APP_RULE 행 없음 */
    @Test
    void singleSignalsAreRecordedNotFp() {
        List<BenignSent> sent = logins(3);
        List<BenignAppAlert> app = List.of(
                app("100232", "r1", 10), app("100230", "r2", 510), app("100232", "r3", 1010));
        Map<String, BenignResult> by = link(sent, rids(3), app, List.of());

        for (int s = 1; s <= 3; s++) {
            assertFalse(by.containsKey(s + ":APP_RULE"), "login 에는 APP_RULE 행을 만들지 않는다 (seq " + s + ")");
            BenignResult bc = by.get(s + ":BACKEND_CORR");
            assertFalse(bc.alerted(), "100230/100232 는 FP 가 아니다 (seq " + s + ")");
            assertEquals(0, bc.alertCount());
        }
        assertEquals(List.of("100232"), by.get("1:BACKEND_CORR").recordedRuleIds());
        assertEquals(List.of("100230"), by.get("2:BACKEND_CORR").recordedRuleIds());
    }

    /** 100231(실패 10회) rid 링크 → BACKEND_CORR FP. 100233(반복 실패 후 성공)도 FP */
    @Test
    void sequenceCorrelationRulesAreFp() {
        List<BenignSent> sent = logins(2);
        Map<String, BenignResult> by = link(sent, rids(2),
                List.of(app("100231", "r1", 10), app("100233", "r2", 510)), List.of());

        assertTrue(by.get("1:BACKEND_CORR").alerted());
        assertEquals(List.of("100231"), by.get("1:BACKEND_CORR").linkedRuleIds());
        assertTrue(by.get("2:BACKEND_CORR").alerted());
        assertEquals(List.of("100233"), by.get("2:BACKEND_CORR").linkedRuleIds());
    }

    /** 오타 후 재시도(401 실패 1 + 200 성공 1)는 임계 미달 → 상관 룰 안 뜸 → BACKEND_CORR FP 0 */
    @Test
    void typoRetryDoesNotTriggerSequenceFp() {
        List<BenignSent> sent = logins(2);
        // 100230(실패 단건) + 100232(성공 단건)만, 100231/100233 없음
        Map<String, BenignResult> by = link(sent, rids(2),
                List.of(app("100230", "r1", 10), app("100232", "r2", 510)), List.of());

        assertEquals(0, by.get("1:BACKEND_CORR").alertCount());
        assertEquals(0, by.get("2:BACKEND_CORR").alertCount());
    }

    /** login NIDS: 1000031(ANALYTIC/BRUTE_FORCE) url+시각창 단일 후보 → NIDS FP. 요청 url 이 모두 같아 창 분리가 관건(§I) */
    @Test
    void loginNidsAnalyticIsFpViaSingleCandidate() {
        List<BenignSent> sent = logins(3);
        Map<String, BenignResult> by = link(sent, rids(3), List.of(),
                List.of(nids(1000031, 2, 20, 900)));   // seq1 창(0~40) 안 event 20ms

        assertTrue(by.get("1:NIDS").alerted());
        assertEquals(List.of("1000031"), by.get("1:NIDS").linkedRuleIds());
        assertFalse(by.get("2:NIDS").alerted());
    }
}
