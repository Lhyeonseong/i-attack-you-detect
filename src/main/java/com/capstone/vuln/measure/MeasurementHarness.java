package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.AttemptRole;
import com.capstone.vuln.correlation.Correlation;
import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.TelemetrySensor;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import com.capstone.vuln.correlation.VerdictResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * op 1개 측정 파이프라인 (S3-5b-2b): 수집(2a) → 기존 엔진 correlate→judge→save "호출" → per-run 요약.
 *
 * <p>판정·상관·match·overestimate·confidence 는 전부 엔진 출력을 쓴다(재구현 금지). harness 가 하는
 * 추가 작업은 (paw, abilityId) 매칭으로 Correlation 에 attackerVerdict 를 꽂는 것뿐이다(결정 B).
 * 20회 반복·게이트 집계는 S3-5b-3.
 *
 * <p>S4-1: 모든 저장에 run_id 를 넘기고(필수), verdict 별 attempt_role 을 정답지 쪽 역할(rid → ATTACK/CONTROL)
 * 에서 정한다 — 멤버가 전부 CONTROL 일 때만 CONTROL. 판정 로직은 건드리지 않는다.
 *
 * <p>S4-1b (Gap #6): correlate 전에 op 시간 범위 [attackTime, opFinish] 안 이벤트를 OperationResolver(Caldera 링크)
 * 로 해석하고, 그 결과가 runOnce opId 와 같을 때만 op_id 를 확정한다(두 독립 원천 교차검증).
 * 불일치·Caldera 실패·범위 밖은 미해석(paw 키, resolved=false → DB op_id NULL) 그대로 — 측정은 계속한다.
 * op 귀속은 라벨이며 alert 매칭(agentPaw)·판정에는 쓰이지 않는다.
 *
 * <p>S4-4 (ADR-S4-01 v1.7 R14·R15): NidsCorrelator 가 있으면 Suricata alert(86601)를 eve http → 시도로 연결해
 * 앱 룰 alert 와 함께 엔진에 넘긴다(ANALYTIC sid 만, control=NIDS). verdict 별 텔레메트리(앱 로그 이벤트 수·
 * 연결된 eve http 수)와 op 창 NIDS 집계(orphan 포함)를 같이 저장한다. 없으면 R14 이전과 같다(앱 룰 alert 만).
 */
public class MeasurementHarness {

    private static final Logger log = LoggerFactory.getLogger(MeasurementHarness.class);

    private final MeasurementCollector collector;
    private final CorrelationEngine correlationEngine;
    private final VerdictEngine verdictEngine;
    private final VerdictRepository verdictRepository;
    private final OperationResolver operationResolver;
    private final NidsCorrelator nidsCorrelator;
    private final NidsWindowRepository nidsWindowRepository;

    public MeasurementHarness(MeasurementCollector collector,
                              CorrelationEngine correlationEngine,
                              VerdictEngine verdictEngine,
                              VerdictRepository verdictRepository,
                              OperationResolver operationResolver) {
        this(collector, correlationEngine, verdictEngine, verdictRepository, operationResolver, null, null);
    }

    public MeasurementHarness(MeasurementCollector collector,
                              CorrelationEngine correlationEngine,
                              VerdictEngine verdictEngine,
                              VerdictRepository verdictRepository,
                              OperationResolver operationResolver,
                              NidsCorrelator nidsCorrelator,
                              NidsWindowRepository nidsWindowRepository) {
        this.collector = collector;
        this.correlationEngine = correlationEngine;
        this.verdictEngine = verdictEngine;
        this.verdictRepository = verdictRepository;
        this.operationResolver = operationResolver;
        this.nidsCorrelator = nidsCorrelator;
        this.nidsWindowRepository = nidsWindowRepository;
    }

    public PerRunSummary measure(UUID runId, String opId, Instant attackTime, Instant opFinish) {
        Objects.requireNonNull(runId, "runId — 모든 verdict 는 run 에 귀속된다");
        CollectedWindow window = collector.collect(opId, attackTime, opFinish);

        List<AttackEvent> attacks = bindOperation(window.attacks(), opId, attackTime, opFinish);
        NidsCorrelator.Result nids = nidsCorrelator == null ? null
                : nidsCorrelator.correlate(attacks, window.requestArgs(), window.nidsAlerts(), window.eveHttp(),
                        operationResolver.links());
        List<AlertEvent> alerts = new ArrayList<>(window.alerts());
        if (nids != null) {
            alerts.addAll(nids.alerts());
        }
        List<Correlation> correlations = correlationEngine.correlate(attacks, alerts);
        for (Correlation c : correlations) {
            // CONTROL 은 공격 지표의 대상이 아니므로 ability 공통 attacker verdict 를 상속하지 않는다.
            boolean control = !c.getEventRids().isEmpty()
                    && c.getEventRids().stream()
                    .allMatch(rid -> window.attemptRoles().get(rid) == AttemptRole.CONTROL);
            if (!control) {
                // (paw, abilityId) 로 매칭 — 없으면 null → 엔진에서 UNKNOWN 유도 (결정 B/C)
                AttackOutcome attacker = window.attackerVerdicts()
                        .get(new PawAbility(c.getKey().agentPaw(), c.getKey().abilityId()));
                c.setAttackerVerdict(attacker);
            }
        }

        List<VerdictResult> verdicts = verdictEngine.judge(correlations);
        Map<String, AttemptRole> roles = roles(verdicts, window.attemptRoles());
        if (nids == null) {
            verdictRepository.save(runId, correlations, verdicts, roles);
        } else {
            verdictRepository.save(runId, correlations, verdicts, roles,
                    telemetry(correlations, verdicts, nids.httpByRid()));
            Instant windowEnd = opFinish.plus(collector.readWindowTail());
            nidsWindowRepository.save(runId, opId, attackTime, windowEnd, nids.counts());
            NidsWindowCounts n = nids.counts();
            System.out.printf("NIDS op=%s alerts=%d orphan=%d analytic=%d linked=%d telemetry=%d marker=%d "
                            + "undecided=%d unclassified=%d http=%d attributed=%d%n",
                    opId, n.nidsAlerts(), n.orphanAlerts(), n.analyticAlerts(), n.analyticLinked(),
                    n.telemetryAlerts(), n.markerAlerts(), n.undecidedAlerts(), n.unclassifiedAlerts(),
                    n.httpEvents(), n.httpAttributed());
        }

        List<ScenarioResult> rows = verdicts.stream().map(v -> toRow(opId, v)).toList();
        PerRunSummary summary = new PerRunSummary(opId, rows);
        print(summary);
        return summary;
    }

    /**
     * unit_key → 센서별 이벤트 수 (R15). APP_LOG = 멤버 correlation 이 묶은 앱 이벤트 수,
     * NIDS = 멤버 이벤트 rid 에 연결된(R14 c) eve http 수.
     */
    static Map<String, Map<TelemetrySensor, Integer>> telemetry(List<Correlation> correlations,
                                                                 List<VerdictResult> verdicts,
                                                                 Map<String, Integer> httpByRid) {
        Map<String, Correlation> byKey = new LinkedHashMap<>();
        correlations.forEach(c -> byKey.put(c.getCorrelationKey(), c));
        Map<String, Map<TelemetrySensor, Integer>> out = new LinkedHashMap<>();
        for (VerdictResult v : verdicts) {
            int appLog = 0;
            int nidsHttp = 0;
            for (String key : v.memberCorrelationIds()) {
                Correlation c = byKey.get(key);
                if (c == null) {
                    continue;
                }
                appLog += c.getEventCount();
                for (String rid : c.getEventRids()) {
                    nidsHttp += httpByRid.getOrDefault(rid, 0);
                }
            }
            Map<TelemetrySensor, Integer> sensors = new EnumMap<>(TelemetrySensor.class);
            sensors.put(TelemetrySensor.APP_LOG, appLog);
            sensors.put(TelemetrySensor.NIDS, nidsHttp);
            out.put(v.unitKey(), sensors);
        }
        return out;
    }

    /**
     * op 범위 안 이벤트만 resolver 에 넘기고, resolver 가 runOnce opId 로 해석한 키만 채택한다.
     * 다른 op 로 해석된 이벤트는 원래(미해석) 키로 되돌리고 불일치를 로그 1줄로 남긴다.
     */
    private List<AttackEvent> bindOperation(List<AttackEvent> events, String opId, Instant attackTime, Instant opFinish) {
        List<AttackEvent> inRange = events.stream()
                .filter(e -> !e.attackTime().isBefore(attackTime) && !e.attackTime().isAfter(opFinish))
                .toList();
        List<AttackEvent> resolved = operationResolver.resolve(inRange);
        Map<AttackEvent, AttackEvent> byOriginal = new IdentityHashMap<>();
        for (int i = 0; i < inRange.size(); i++) {
            byOriginal.put(inRange.get(i), resolved.get(i));
        }

        Set<String> otherOps = new TreeSet<>();
        int mismatched = 0;
        List<AttackEvent> bound = new ArrayList<>(events.size());
        for (AttackEvent original : events) {
            AttackEvent r = byOriginal.get(original);
            if (r == null || !r.key().opIdResolved()) {
                bound.add(original); // 범위 밖 · Caldera 실패 · 후보 0/2개↑ → 미해석 그대로
            } else if (r.key().opId().equals(opId)) {
                bound.add(r);
            } else {
                otherOps.add(r.key().opId());
                mismatched++;
                bound.add(original);
            }
        }
        if (mismatched > 0) {
            log.warn("op_id 교차검증 불일치 — runOnce opId={} vs Caldera 링크 해석 {} ({}건) → op_id 미기록(resolved=false)",
                    opId, otherOps, mismatched);
        }
        return bound;
    }

    /** unit_key → 역할. 멤버(correlationKey = 대표 rid)가 모두 CONTROL 이면 CONTROL, 그 외 ATTACK */
    static Map<String, AttemptRole> roles(List<VerdictResult> verdicts, Map<String, AttemptRole> ridRoles) {
        Map<String, AttemptRole> roles = new LinkedHashMap<>();
        for (VerdictResult v : verdicts) {
            boolean control = !v.memberCorrelationIds().isEmpty() && v.memberCorrelationIds().stream()
                    .allMatch(key -> ridRoles.get(key) == AttemptRole.CONTROL);
            roles.put(v.unitKey(), control ? AttemptRole.CONTROL : AttemptRole.ATTACK);
        }
        return roles;
    }

    private static ScenarioResult toRow(String opId, VerdictResult v) {
        String rid = v.memberCorrelationIds().isEmpty() ? null : v.memberCorrelationIds().get(0);
        return new ScenarioResult(
                v.scenario(), v.unitType(), opId, rid,
                v.gtOutcome(), v.attackerVerdict(), v.attackerMatch(), v.overestimate(),
                v.verdict(), v.bestConfidence(), v.detectionStatus(), v.mttdMs());
    }

    private static void print(PerRunSummary summary) {
        System.out.println("PER-RUN op=" + summary.opId() + " rows=" + summary.results().size());
        for (ScenarioResult r : summary.results()) {
            System.out.printf(
                    "  [%s/%s] rid=%s gt=%s attacker=%s match=%s overestimate=%s verdict=%s conf=%.2f detection=%s mttdMs=%s%n",
                    r.scenario(), r.unitKind(), r.rid(), r.gtOutcome(), r.attackerVerdict(),
                    r.attackerMatch(), r.overestimate(), r.verdict(), r.bestConfidence(),
                    r.detectionStatus(), r.mttdMs());
        }
    }
}
