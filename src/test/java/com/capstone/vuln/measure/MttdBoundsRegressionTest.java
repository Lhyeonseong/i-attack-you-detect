package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.Correlation;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.DetectionStatus;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * MTTD-1 회귀 (2026-10-21 조사, 증거 2026-10-21_mttd-1-outlier.log Step 3-4).
 *
 * <p>측정 경로에서 mttd 는 읽기 창 [attackTime, opFinish + 30s] 로 묶인다: 앱 줄은 GtLogReader 가 창 밖을 버리고,
 * alert 는 인덱서 range 질의가 창 밖을 가져오지 않으며, 엔진은 공격보다 이른 alert 를 링크하지 않는다.
 * 실제 수집기·리더·엔진을 쓰고 인덱서만 range 를 지키는 가짜로 대신한다(질의 바디의 range 값은 따로 확인).
 */
class MttdBoundsRegressionTest {

    private static final long START = 1_792_524_000_000L;            // 2026-10-20T19:20:00Z
    private static final Instant ATTACK_TIME = Instant.ofEpochMilli(START);
    private static final long DURATION_MS = 100_000;                  // op 소요 100s
    private static final Instant OP_FINISH = ATTACK_TIME.plusMillis(DURATION_MS);
    private static final Duration TAIL = MeasurementCollector.DEFAULT_READ_WINDOW_TAIL;
    private static final long UPPER_BOUND_MS = DURATION_MS + TAIL.toMillis();
    private static final long THREE_HOURS_MS = Duration.ofHours(3).toMillis();
    private static final UUID RUN_ID = UUID.fromString("00000000-0000-0000-0000-00000000d001");

    private static final String PAW = "zetofr";
    private static final String PT_ABILITY = "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
    private static final String SSRF_ABILITY = "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
    private static final String BF_ABILITY = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";

    private static final DateTimeFormatter WAZUH_TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSxx").withZone(ZoneOffset.UTC);

    private record AlertFixture(long timeMs, String json) {
    }

    /** 인덱서 대역: range(timestamp, gte/lte) 를 지켜 창 안 alert 만 돌려주고, 받은 창을 기록한다 */
    private static final class RangeHonoringIndexer implements AlertSearchSource {
        private final List<AlertFixture> alerts;
        Instant from;
        Instant to;

        RangeHonoringIndexer(List<AlertFixture> alerts) {
            this.alerts = alerts;
        }

        @Override
        public String search(Instant fromInclusive, Instant toInclusive) {
            from = fromInclusive;
            to = toInclusive;
            List<String> hits = alerts.stream()
                    .filter(a -> a.timeMs() >= fromInclusive.toEpochMilli() && a.timeMs() <= toInclusive.toEpochMilli())
                    .map(a -> "{\"_source\":" + a.json() + "}")
                    .toList();
            return "{\"hits\":{\"hits\":[" + String.join(",", hits) + "]}}";
        }
    }

    private static String appLine(long timeMs, String rid, String ability, String path, String technique,
                                  String outcome, String args) {
        return """
                {"time":%d,"rid":"%s","correlation":{"op_id":"%s","ability_id":"%s","source":"HEADER"},"validation":{"outcome":"%s","technique_id":"%s"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"%s"},"args":"%s"}}"""
                .formatted(timeMs, rid, PAW, ability, outcome, technique, path, args);
    }

    private static AlertFixture alert(long timeMs, String ruleId, String rid, String ability, String path,
                                      String technique, String args) {
        return new AlertFixture(timeMs, """
                {"timestamp":"%s","rule":{"id":"%s"},"data":{"rid":"%s","correlation":{"op_id":"%s","ability_id":"%s","source":"HEADER"},"src_endpoint":{"ip":"172.20.0.1"},"validation":{"technique_id":"%s"},"http_request":{"url":{"path":"%s"},"args":"%s"}}}"""
                .formatted(WAZUH_TS.format(Instant.ofEpochMilli(timeMs)), ruleId, rid, PAW, ability, technique, path, args));
    }

    private static String ptLine(long timeMs, String rid) {
        return appLine(timeMs, rid, PT_ABILITY, "/api/files/download", "T1190", "SUCCEEDED",
                "filename=../../../../etc/passwd");
    }

    private static AlertFixture ptAlert(long timeMs, String rid) {
        return alert(timeMs, "100220", rid, PT_ABILITY, "/api/files/download", "T1190",
                "filename=../../../../etc/passwd");
    }

    private static MeasurementCollector collector(List<String> appLines, AlertSearchSource indexer) {
        String log = String.join("\n", appLines);
        return new MeasurementCollector(new GtLogReader(() -> log), new AlertIndexReader(indexer),
                new AttackerVerdictResolver(id -> "{\"chain\":[]}"), TAIL);
    }

    private static PerRunSummary measure(MeasurementCollector collector, VerdictRepository repo) {
        MeasurementHarness harness = new MeasurementHarness(collector, new CorrelationEngine(), new VerdictEngine(),
                repo, new OperationResolver(List::of));
        return harness.measure(RUN_ID, "op-mttd-1", ATTACK_TIME, OP_FINISH);
    }

    @SuppressWarnings("unchecked")
    private static List<Correlation> savedCorrelations(VerdictRepository repo) {
        ArgumentCaptor<List<Correlation>> correlations = ArgumentCaptor.forClass(List.class);
        verify(repo).save(eq(RUN_ID), correlations.capture(), anyList(), anyMap());
        return correlations.getValue();
    }

    @Test
    void taggedPathTraversalLineOutsideReadWindowYieldsNoCorrelationEvenWithSameRidAlertInside() {
        // (a) 3시간 전 Caldera 태그 PT 줄 + 같은 rid 의 alert 는 창 안(+1s) — 앱 줄 쪽 창 필터만으로 막혀야 한다
        String rid = "rid-old-pt";
        RangeHonoringIndexer indexer = new RangeHonoringIndexer(List.of(ptAlert(START + 1_000, rid)));
        MeasurementCollector collector = collector(List.of(ptLine(START - THREE_HOURS_MS, rid)), indexer);

        CollectedWindow window = collector.collect("op-mttd-1", ATTACK_TIME, OP_FINISH);
        assertEquals(0, window.attacks().size(), "창 밖 앱 줄은 수집되지 않는다");
        assertEquals(1, window.alerts().size(), "alert 는 창 안이라 수집된다 — 차단은 앱 줄 쪽에서만 일어남");

        VerdictRepository repo = mock(VerdictRepository.class);
        PerRunSummary summary = measure(collector, repo);

        assertEquals(0, savedCorrelations(repo).size(), "correlation 0");
        assertEquals(0, summary.results().size());
    }

    @Test
    void alertsOnlyOutsideReadWindowYieldNotDetectedAndQueryRangeIsAttackTimeToOpFinishPlus30s() {
        // (b) 창 안 PT 공격 + 같은 rid alert 는 창 밖에만(opFinish+31s, +3h) → 링크 없음, NOT_DETECTED
        String rid = "rid-pt";
        RangeHonoringIndexer indexer = new RangeHonoringIndexer(List.of(
                ptAlert(OP_FINISH.toEpochMilli() + 31_000, rid),
                ptAlert(START + 5_000 + THREE_HOURS_MS, rid)));

        PerRunSummary summary = measure(collector(List.of(ptLine(START + 5_000, rid)), indexer),
                mock(VerdictRepository.class));

        // 인덱서에 넘긴 창 = [attackTime, opFinish + 30s], 질의 바디의 range 도 그 값
        assertEquals(ATTACK_TIME, indexer.from);
        assertEquals(OP_FINISH.plus(TAIL), indexer.to);
        String body = IndexerAlertSearchSource.searchBody(indexer.from.toEpochMilli(), indexer.to.toEpochMilli(),
                "vuln-webapp");
        assertTrue(body.contains("\"gte\":" + START), body);
        assertTrue(body.contains("\"lte\":" + (START + UPPER_BOUND_MS)), body);

        assertEquals(1, summary.results().size());
        ScenarioResult pt = summary.results().get(0);
        assertEquals("PATH_TRAVERSAL", pt.scenario());
        assertEquals(DetectionStatus.NOT_DETECTED, pt.detectionStatus());
        assertNull(pt.mttdMs());
    }

    @Test
    void everyMeasuredMttdStaysWithinZeroAndDurationPlus30s() {
        // (c) 하네스 불변식 0 ≤ mttd ≤ durationMs + 30s — 정상 탐지·상한 경계(창 끝 alert)·공격보다 이른 alert·BF 시퀀스
        List<String> lines = new ArrayList<>();
        List<AlertFixture> alerts = new ArrayList<>();

        lines.add(ptLine(START + 5_000, "rid-pt-normal"));
        alerts.add(ptAlert(START + 6_200, "rid-pt-normal"));

        // 상한 경계: opFinish 시점 공격 + 창 끝(opFinish+30s) 정확히의 alert — 관찰 30s 경계에 걸림
        lines.add(ptLine(OP_FINISH.toEpochMilli(), "rid-pt-edge"));
        alerts.add(ptAlert(OP_FINISH.toEpochMilli() + TAIL.toMillis(), "rid-pt-edge"));

        // 공격(+10s)보다 이른(+8s) 같은 rid alert — 링크되면 음수 mttd 가 되므로 링크되지 않아야 한다
        lines.add(ptLine(START + 10_000, "rid-pt-early"));
        alerts.add(ptAlert(START + 8_000, "rid-pt-early"));

        // SSRF: 공격 시각 = attackTime(창 시작) 정확히, alert 는 창 끝 정확히 → mttd 가 상한 durationMs+30s 와 같음(늦은 탐지)
        lines.add(appLine(START, "rid-ssrf-late", SSRF_ABILITY, "/api/preview", "T1190", "SUCCEEDED",
                "url=http://169.254.169.254/latest/meta-data/"));
        alerts.add(alert(START + UPPER_BOUND_MS, "100240", "rid-ssrf-late", SSRF_ABILITY, "/api/preview", "T1190",
                "url=http://169.254.169.254/latest/meta-data/"));

        // BF: 실패 12회(+20s~+31s) 뒤 성공 1회(+32s), 실패마다 100230 alert(+0.4s)
        for (int i = 0; i < 12; i++) {
            long t = START + 20_000 + i * 1_000L;
            lines.add(appLine(t, "rid-bf-f" + i, BF_ABILITY, "/api/auth/login", "T1110", "FAILED", "username=user1"));
            alerts.add(alert(t + 400, "100230", "rid-bf-f" + i, BF_ABILITY, "/api/auth/login", "T1110",
                    "username=user1"));
        }
        lines.add(appLine(START + 32_000, "rid-bf-s", BF_ABILITY, "/api/auth/login", "T1110", "SUCCEEDED",
                "username=user1"));

        PerRunSummary summary = measure(collector(lines, new RangeHonoringIndexer(alerts)),
                mock(VerdictRepository.class));

        List<Long> mttds = summary.results().stream().map(ScenarioResult::mttdMs).filter(m -> m != null).toList();
        for (long mttd : mttds) {
            assertTrue(mttd >= 0 && mttd <= UPPER_BOUND_MS,
                    "mttd " + mttd + " 가 [0, " + UPPER_BOUND_MS + "] 밖 — " + summary.results());
        }
        // 비어 있는 검사가 아님을 확인: 탐지 4건(PT 정상·PT 경계·SSRF 늦은 탐지·BF), 상한 경계 도달 1건, 이른 alert 건은 미탐
        assertEquals(4, mttds.size(), summary.results().toString());
        assertTrue(mttds.contains(UPPER_BOUND_MS), "상한 경계(durationMs+30s) 포함: " + mttds);
        ScenarioResult early = summary.results().stream().filter(r -> "rid-pt-early".equals(r.rid())).findFirst()
                .orElseThrow();
        assertEquals(DetectionStatus.NOT_DETECTED, early.detectionStatus());
        assertNull(early.mttdMs());
    }
}
