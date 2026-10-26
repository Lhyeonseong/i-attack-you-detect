package com.capstone.vuln.correlation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 로그의 correlation.op_id(= agent paw)를 Caldera operation UUID 로 보강한다 (S3-3 경로 B)
 *
 * Caldera 에는 operation UUID 를 ability 에 넣는 예약변수가 없고, 같은 paw 가 여러 operation 에
 * 재사용되므로 paw 단독 매핑은 불가하다. (paw, ability_id, 이벤트 time) 이 링크의
 * [decide, finish] 안에 드는 operation 이 정확히 1개일 때만 UUID 로 치환한다.
 * API 실패·후보 0/2개↑ 이면 paw 를 그대로 두고 opIdResolved=false.
 */
public class OperationResolver {

    private static final Logger log = LoggerFactory.getLogger(OperationResolver.class);

    private final CalderaOperationsClient client;

    public OperationResolver(CalderaOperationsClient client) {
        this.client = client;
    }

    /** 배치당 Caldera API 1회 조회 */
    public List<AttackEvent> resolve(List<AttackEvent> events) {
        List<OperationLink> links;
        try {
            links = client.fetchLinks();
        } catch (RuntimeException e) {
            log.warn("Caldera operation 조회 실패 — paw 로 대체 (opIdResolved=false): {}", e.toString());
            return events;
        }
        return events.stream()
                .map(e -> e.withKey(resolveKey(e, links)))
                .toList();
    }

    /**
     * Caldera 링크 목록 (R14 c 의 op 창 — resolve 와 같은 [decide, finish+1s]). 조회 실패면 빈 목록(→ NIDS 연결 없음)
     */
    public List<OperationLink> links() {
        try {
            return client.fetchLinks();
        } catch (RuntimeException e) {
            log.warn("Caldera operation 조회 실패 — NIDS http 를 시도에 연결하지 않는다: {}", e.toString());
            return List.of();
        }
    }

    private static CorrelationKey resolveKey(AttackEvent event, List<OperationLink> links) {
        CorrelationKey key = event.key();
        if (key.agentPaw() == null) {
            return key;
        }
        Set<String> operations = links.stream()
                .filter(l -> key.agentPaw().equals(l.paw()))
                .filter(l -> key.abilityId() == null || key.abilityId().equals(l.abilityId()))
                .filter(l -> l.covers(event.attackTime()))
                .map(OperationLink::opId)
                .collect(Collectors.toSet());
        return operations.size() == 1 ? key.resolvedTo(operations.iterator().next()) : key;
    }
}
