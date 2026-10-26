package com.capstone.vuln.correlation;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OperationResolverTest {

    private static final String PAW = "djlycn";
    private static final String BF_ABILITY = "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";
    private static final String OP_RUN1 = "b08f0883-e87a-4509-98e0-a1945fdafc77";
    private static final String OP_RUN2 = "736ab6e7-bd4b-4b67-907b-a4e3cac8047f";

    /** 실측(2026-10-11): 같은 paw·ability 가 두 operation 에 모두 있고 시각으로만 구분된다 */
    private static final List<OperationLink> LINKS = List.of(
            new OperationLink(OP_RUN1, PAW, BF_ABILITY,
                    Instant.parse("2026-10-11T12:17:55Z"), Instant.parse("2026-10-11T12:18:36Z")),
            new OperationLink(OP_RUN2, PAW, BF_ABILITY,
                    Instant.parse("2026-10-11T13:30:55Z"), Instant.parse("2026-10-11T13:31:42Z")));

    private static AttackEvent bfEvent(Instant time) {
        return new AttackEvent(new CorrelationKey(PAW, BF_ABILITY, "rid-1"), "BRUTE_FORCE", "T1110",
                time, "172.20.0.1", "/api/auth/login", "admin", GroundTruthOutcome.FAILED);
    }

    @Test
    void pawIsReplacedByOperationUuidChosenByLinkTimeWindow() {
        OperationResolver resolver = new OperationResolver(() -> LINKS);

        List<AttackEvent> resolved = resolver.resolve(List.of(
                bfEvent(Instant.parse("2026-10-11T12:18:00.500Z")),
                // finish 는 초 절삭 — 실측 마지막 BF 이벤트 13:31:42.158 도 run2 로 해석돼야 한다
                bfEvent(Instant.parse("2026-10-11T13:31:42.158Z"))));

        CorrelationKey k1 = resolved.get(0).key();
        assertEquals(OP_RUN1, k1.opId());
        assertEquals(PAW, k1.agentPaw());
        assertTrue(k1.opIdResolved());

        CorrelationKey k2 = resolved.get(1).key();
        assertEquals(OP_RUN2, k2.opId());
        assertEquals(PAW, k2.agentPaw());
        assertTrue(k2.opIdResolved());
    }

    @Test
    void apiFailureFallsBackToPawAndMarksUnresolved() {
        OperationResolver resolver = new OperationResolver(() -> {
            throw new IllegalStateException("caldera unreachable");
        });

        CorrelationKey k = resolver.resolve(List.of(bfEvent(Instant.parse("2026-10-11T12:18:00Z")))).get(0).key();

        assertEquals(PAW, k.opId());
        assertEquals(PAW, k.agentPaw());
        assertFalse(k.opIdResolved());
    }

    @Test
    void eventOutsideAnyLinkWindowStaysUnresolved() {
        OperationResolver resolver = new OperationResolver(() -> LINKS);

        CorrelationKey k = resolver.resolve(List.of(bfEvent(Instant.parse("2026-10-11T14:00:00Z")))).get(0).key();

        assertEquals(PAW, k.opId());
        assertFalse(k.opIdResolved());
    }

    @Test
    void parsesOperationChainLinksFromApiResponse() {
        String json = """
                [{"id":"736ab6e7-bd4b-4b67-907b-a4e3cac8047f","name":"S2-SSRF-validation-01","state":"running",
                  "host_group":[{"paw":"djlycn"}],
                  "chain":[
                    {"id":"l1","paw":"djlycn","ability":{"ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","technique_id":"T1110"},
                     "decide":"2026-10-11T13:30:55Z","finish":"2026-10-11T13:31:42Z"},
                    {"id":"l2","paw":"djlycn","ability":{"ability_id":"a7f3c1d9","technique_id":"T1190"},
                     "decide":"2026-10-11T13:32:00Z","finish":""}]}]
                """;

        List<OperationLink> links = CalderaOperationsHttpClient.parseLinks(json);

        assertEquals(2, links.size());
        OperationLink first = links.get(0);
        assertEquals("736ab6e7-bd4b-4b67-907b-a4e3cac8047f", first.opId());
        assertEquals("djlycn", first.paw());
        assertEquals("7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d", first.abilityId());
        assertEquals(Instant.parse("2026-10-11T13:30:55Z"), first.decide());
        assertEquals(Instant.parse("2026-10-11T13:31:42Z"), first.finish());
        assertNull(links.get(1).finish());
    }
}
