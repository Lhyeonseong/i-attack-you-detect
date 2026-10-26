package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MeasurementCollectorTest {

    private static final long START = 1_000_000_000_000L;
    private static final Instant ATTACK_TIME = Instant.ofEpochMilli(START);
    private static final Instant OP_FINISH = Instant.ofEpochMilli(START + 100_000); // +100s
    private static final Duration TAIL = Duration.ofSeconds(30);

    // opFinish+29s(포함) 1줄 + opFinish+31s(제외, tail 밖) 1줄
    private static final String LOG = """
            {"time":1000000129000,"rid":"rid-in","correlation":{"op_id":"mcukpa","ability_id":"7aa89a87","source":"HEADER"},"validation":{"outcome":"FAILED","technique_id":"T1110"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/auth/login"},"args":"username=user1"}}
            {"time":1000000131000,"rid":"rid-out","correlation":{"op_id":"mcukpa","ability_id":"7aa89a87","source":"HEADER"},"validation":{"outcome":"FAILED","technique_id":"T1110"},"src_endpoint":{"ip":"172.20.0.1"},"http_request":{"url":{"path":"/api/auth/login"},"args":"username=user1"}}
            """;

    private static final String ALERTS = """
            {"hits":{"hits":[{"_source":{"timestamp":"2026-10-16T10:35:05.609+0000","rule":{"id":"100230"},
              "data":{"rid":"rid-in","correlation":{"op_id":"mcukpa","ability_id":"7aa89a87","source":"HEADER"},
              "src_endpoint":{"ip":"172.20.0.1"},"validation":{"technique_id":"T1110"},
              "http_request":{"url":{"path":"/api/auth/login"},"args":"username=user1"}}}}]}}""";

    private static final String OP_FACTS = """
            {"chain":[{"paw":"mcukpa","ability":{"ability_id":"7aa89a87"},
              "facts":[{"trait":"bf.verdict","value":"SUCCEEDED"}]}]}""";

    @Test
    void collect_merges_three_sources_and_bounds_window_by_opFinish_plus_tail() {
        Instant[] alertWindow = new Instant[2];
        AlertSearchSource alertSrc = (from, to) -> {
            alertWindow[0] = from;
            alertWindow[1] = to;
            return ALERTS;
        };

        MeasurementCollector collector = new MeasurementCollector(
                new GtLogReader(() -> LOG),
                new AlertIndexReader(alertSrc),
                new AttackerVerdictResolver(id -> OP_FACTS),
                TAIL);

        CollectedWindow window = collector.collect("op-uuid", ATTACK_TIME, OP_FINISH);

        // 읽기 창 = [attackTime, opFinish + 30s]
        assertEquals(ATTACK_TIME, alertWindow[0]);
        assertEquals(OP_FINISH.plus(TAIL), alertWindow[1]);

        // gt: tail 안(+29s) 포함, tail 밖(+31s) 제외
        assertEquals(1, window.attacks().size());
        assertEquals("rid-in", window.attacks().get(0).key().rid());

        assertEquals(1, window.alerts().size());
        assertEquals(AttackOutcome.SUCCEEDED,
                window.attackerVerdicts().get(new PawAbility("mcukpa", "7aa89a87")));
        assertTrue(window.attackerVerdicts().size() == 1);
    }
}
