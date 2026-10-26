package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.AttemptRole;

import java.util.List;
import java.util.Map;

/**
 * op 1개 창에서 수집한 묶음 (b-2b 입력). 판정·상관·저장은 하지 않는다.
 * - attacks: 앱 OCSF 로그에서 만든 AttackEvent (gt_outcome 포함)
 * - alerts: 인덱서에서 만든 AlertEvent (앱 로그 룰, vuln-webapp 그룹)
 * - attackerVerdicts: Caldera facts 의 (paw, abilityId) → attacker_verdict. fact 없으면 키 자체가 없음(→UNKNOWN 유도)
 * - attemptRoles: rid → 시도 역할(ATTACK/CONTROL, 정답지 쪽 판별). 없는 rid 는 ATTACK
 * - nidsAlerts: 인덱서 rule.id 86601 (R14 a), eveHttp: eve.json http 이벤트 (R14 b·c)
 * - requestArgs: rid → 앱 로그 http_request.args (R14 c URL 비교)
 */
public record CollectedWindow(List<AttackEvent> attacks,
                              List<AlertEvent> alerts,
                              Map<PawAbility, AttackOutcome> attackerVerdicts,
                              Map<String, AttemptRole> attemptRoles,
                              List<NidsAlert> nidsAlerts,
                              List<EveHttp> eveHttp,
                              Map<String, String> requestArgs) {

    public CollectedWindow(List<AttackEvent> attacks, List<AlertEvent> alerts,
                           Map<PawAbility, AttackOutcome> attackerVerdicts, Map<String, AttemptRole> attemptRoles) {
        this(attacks, alerts, attackerVerdicts, attemptRoles, List.of(), List.of(), Map.of());
    }

    public CollectedWindow(List<AttackEvent> attacks, List<AlertEvent> alerts,
                           Map<PawAbility, AttackOutcome> attackerVerdicts) {
        this(attacks, alerts, attackerVerdicts, Map.of());
    }
}
