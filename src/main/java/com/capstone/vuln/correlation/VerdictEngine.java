package com.capstone.vuln.correlation;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Correlation → Verdict 7상태 판정 (순수 함수, 입력 Correlation 을 변경하지 않는다)
 *
 * 1) Verdict 단위로 묶는다: 단건형 SINGLE / BF 계정 집중형 BF_SEQUENCE / 스프레이 SPRAY_CAMPAIGN
 *    (spray=true 인 Correlation 은 같은 segmentId 끼리 캠페인 1건 — 멤버는 개별 Verdict 를 내지 않는다)
 * 2) 탐지 상태는 confidence ≥ 0.7 링크의 alert 만으로 시나리오 기준에 따라 판정한다 (결정3).
 *    정답지는 탐지 상태 계산에 쓰지 않고 결정표(decide)에서만 쓴다 (B안).
 * 3) 관찰기간 안 alert 만으로 initialVerdict, 늦은 alert 까지 포함해 verdict 를 낸다 (결정4).
 */
public class VerdictEngine {

    /**
     * 판정 규칙 버전 — 저장 시 verdict_result.engine_version (S5 재검증 Before/After 비교용).
     * s4-v1: compromise(AN1276)가 하위 룰 100233 도 받는다(ADR-S4-01 v1.7 R16)
     */
    public static final String ENGINE_VERSION = "s4-v1";

    /** docker/config/wazuh_manager/rules/vuln_rules.xml 정의 — BF 로그인 실패(401) 단건 */
    static final String BF_FAILURE_RULE_ID = "100230";
    /** docker/config/wazuh_manager/rules/vuln_rules.xml 정의 — BF 로그인 성공(200) 단건 */
    static final String BF_SUCCESS_RULE_ID = "100232";
    /**
     * vuln_rules.xml 100233 — 100232 의 하위 룰(반복 실패 후 성공). Wazuh 는 같은 이벤트에서 하위 룰을 우선해
     * 100232 를 내지 않으므로(ADR-S4-01 v1.7 R16, 실측 100232 = 0·100233 = 20) 성공 alert 로 함께 본다
     */
    static final String BF_COMPROMISE_RULE_ID = "100233";

    private final int sprayAccountThreshold;

    public VerdictEngine() {
        this(CorrelationEngine.DEFAULT_SPRAY_ACCOUNT_THRESHOLD);
    }

    public VerdictEngine(int sprayAccountThreshold) {
        this.sprayAccountThreshold = sprayAccountThreshold;
    }

    public record Decision(Verdict verdict, UncertainReason reason) {
    }

    /** 탐지 기준 평가: criterionTime = 기준을 충족시킨 alert 시각, compromiseTime = AN1276 성공 alert 시각 */
    private record Detection(DetectionStatus status, Instant criterionTime, Instant compromiseTime) {
        static final Detection NONE = new Detection(DetectionStatus.NOT_DETECTED, null, null);

        static Detection at(Instant criterionTime, Instant compromiseTime) {
            return new Detection(DetectionStatus.DETECTED, criterionTime, compromiseTime);
        }
    }

    private record Unit(UnitType type, List<Correlation> members) {
        Correlation first() { return members.get(0); }

        Instant attackTime() {
            return members.stream().map(Correlation::getAttackTime).min(Comparator.naturalOrder()).orElseThrow();
        }

        Instant observedUntil() {
            return members.stream().map(Correlation::getObservedUntil).max(Comparator.naturalOrder()).orElseThrow();
        }

        List<DetectionLink> links() {
            return members.stream().flatMap(c -> c.getLinks().stream()).toList();
        }

        String unitKey() {
            return type == UnitType.SPRAY_CAMPAIGN
                    ? "spray:" + first().getSegmentId()
                    : "unit:" + first().getCorrelationKey();
        }
    }

    public List<VerdictResult> judge(List<Correlation> correlations) {
        List<Unit> units = new ArrayList<>();
        Map<String, List<Correlation>> campaigns = new LinkedHashMap<>();
        for (Correlation c : correlations) {
            if (c.isSpray() && c.getSegmentId() != null) {
                campaigns.computeIfAbsent(c.getSegmentId(), s -> new ArrayList<>()).add(c);
            } else {
                boolean bruteForce = CorrelationEngine.BRUTE_FORCE_TECHNIQUE.equals(c.getTechniqueId());
                units.add(new Unit(bruteForce ? UnitType.BF_SEQUENCE : UnitType.SINGLE, List.of(c)));
            }
        }
        campaigns.values().forEach(members -> units.add(new Unit(UnitType.SPRAY_CAMPAIGN, members)));
        units.sort(Comparator.comparing(Unit::attackTime));
        return units.stream().map(this::judge).toList();
    }

    private VerdictResult judge(Unit unit) {
        List<DetectionLink> all = unit.links();
        Instant observedUntil = unit.observedUntil();
        List<DetectionLink> inWindow = all.stream()
                .filter(l -> !l.alertTime().isAfter(observedUntil))
                .toList();

        Detection initial = detect(unit, inWindow);
        Detection fin = detect(unit, all);

        GroundTruthOutcome gt = aggregate(unit.members().stream()
                .map(c -> c.getGtOutcome() == null ? GroundTruthOutcome.UNKNOWN : c.getGtOutcome())
                .toList());
        List<GroundTruthOutcome> attackerFacts = unit.members().stream()
                .map(c -> GroundTruthOutcome.fromAttackOutcome(c.getAttackerVerdict()))
                .filter(Objects::nonNull)
                .toList();
        GroundTruthOutcome attacker = attackerFacts.isEmpty() ? null : aggregate(attackerFacts);

        Decision initialDecision = decide(gt, attacker != null, initial.status(), !inWindow.isEmpty(), best(inWindow));
        Decision finalDecision = decide(gt, attacker != null, fin.status(), !all.isEmpty(), best(all));

        Boolean attackerMatch = gt == GroundTruthOutcome.UNKNOWN || attacker == null ? null : attacker == gt;
        boolean overestimate = attacker == GroundTruthOutcome.SUCCEEDED && gt == GroundTruthOutcome.FAILED;
        Long mttdMs = fin.criterionTime() == null ? null
                : Duration.between(unit.attackTime(), fin.criterionTime()).toMillis();
        boolean bruteForce = unit.type() == UnitType.BF_SEQUENCE;

        return new VerdictResult(
                unit.type(),
                unit.unitKey(),
                unit.first().getScenario(),
                unit.first().getTechniqueId(),
                unit.members().stream().map(Correlation::getCorrelationKey).toList(),
                finalDecision.verdict(),
                initialDecision.verdict(),
                finalDecision.reason(),
                fin.status(),
                gt,
                attacker,
                attackerMatch,
                overestimate,
                best(all),
                mttdMs,
                initial.status() != fin.status(),
                bruteForce ? fin.compromiseTime() != null : null,
                bruteForce ? fin.compromiseTime() : null,
                unit.type() == UnitType.SPRAY_CAMPAIGN ? unit.first().getSprayAccountCount() : 0);
    }

    /**
     * 결정표 (우선순위 순)
     * 1. 정답지 UNKNOWN → UNCERTAIN (공격자 fact 도 없으면 NO_EVIDENCE, 있으면 GT_UNKNOWN)
     * 2. 링크는 있으나 최고 confidence < 0.7 → UNCERTAIN (LOW_CONFIDENCE)
     * 3. BLOCKED → SUCCEEDED_BLOCKED / BLOCKED
     * 4~7. SUCCEEDED/FAILED × DETECTED/NOT_DETECTED
     */
    public static Decision decide(GroundTruthOutcome gt, boolean attackerFactPresent, DetectionStatus status,
                                  boolean hasLinks, double bestConfidence) {
        if (gt == null || gt == GroundTruthOutcome.UNKNOWN) {
            return new Decision(Verdict.UNCERTAIN,
                    attackerFactPresent ? UncertainReason.GT_UNKNOWN : UncertainReason.NO_EVIDENCE);
        }
        if (hasLinks && !new Confidence(bestConfidence).usableForVerdict()) {
            return new Decision(Verdict.UNCERTAIN, UncertainReason.LOW_CONFIDENCE);
        }
        boolean succeeded = gt == GroundTruthOutcome.SUCCEEDED;
        Verdict verdict = switch (status) {
            // 현 파이프라인에선 도달 불가: S0 실측 IDS 탐지전용·Wazuh AR 비활성 — 확장설계
            case BLOCKED -> succeeded ? Verdict.SUCCEEDED_BLOCKED : Verdict.BLOCKED;
            case DETECTED -> succeeded ? Verdict.SUCCEEDED_DETECTED : Verdict.FAILED_DETECTED;
            case NOT_DETECTED -> succeeded ? Verdict.SUCCEEDED_MISSED : Verdict.FAILED_UNSEEN;
        };
        return new Decision(verdict, null);
    }

    private Detection detect(Unit unit, List<DetectionLink> links) {
        List<DetectionLink> usable = links.stream()
                .filter(DetectionLink::usable)
                .sorted(Comparator.comparing(DetectionLink::alertTime))
                .toList();
        return switch (unit.type()) {
            case SINGLE -> detectSingle(unit.first().getTechniqueId(), usable);
            case BF_SEQUENCE -> detectBruteForce(usable);
            case SPRAY_CAMPAIGN -> detectSpray(unit.first().getSrcIp(), usable);
        };
    }

    /** 단건형 (SQLi·PT·SSRF): 기법 일치 alert 1건 이상 */
    private static Detection detectSingle(String techniqueId, List<DetectionLink> usable) {
        return usable.stream()
                .filter(l -> Objects.equals(techniqueId, l.technique()))
                .findFirst()
                .map(l -> Detection.at(l.alertTime(), null))
                .orElse(Detection.NONE);
    }

    /**
     * BF 계정 집중형: alert 자신의 srcIp+username 별로 alert time 기준
     * - AN1275: 실패 alert(100230) 120s 내 ≥ 10 → DETECTED, 기준 시각 = 10번째 실패 alert
     * - AN1276: 그 뒤 120s 내 성공 alert(100232 또는 100233) → compromise
     * username 없는 alert 는 계정을 알 수 없으므로 제외 (Correlation 의 username 을 빌려 쓰지 않는다)
     */
    private static Detection detectBruteForce(List<DetectionLink> usable) {
        Map<List<String>, List<DetectionLink>> byAccount = new LinkedHashMap<>();
        usable.stream()
                .filter(l -> BF_FAILURE_RULE_ID.equals(l.ruleId()) || BF_SUCCESS_RULE_ID.equals(l.ruleId())
                        || BF_COMPROMISE_RULE_ID.equals(l.ruleId()))
                .filter(l -> l.srcIp() != null && l.username() != null)
                .forEach(l -> byAccount.computeIfAbsent(List.of(l.srcIp(), l.username()), k -> new ArrayList<>()).add(l));

        Detection earliest = Detection.NONE;
        for (List<DetectionLink> accountAlerts : byAccount.values()) {
            Detection d = bruteForceSequence(accountAlerts);
            if (d.criterionTime() != null
                    && (earliest.criterionTime() == null || d.criterionTime().isBefore(earliest.criterionTime()))) {
                earliest = d;
            }
        }
        return earliest;
    }

    private static Detection bruteForceSequence(List<DetectionLink> accountAlerts) {
        List<DetectionLink> ordered = accountAlerts.stream()
                .sorted(Comparator.comparing(DetectionLink::alertTime)
                        .thenComparing(l -> !BF_FAILURE_RULE_ID.equals(l.ruleId())))
                .toList();
        Deque<Instant> recentFailures = new ArrayDeque<>();
        Instant criterion = null;
        Instant lastThreshold = null;
        Instant compromise = null;
        for (DetectionLink l : ordered) {
            Instant t = l.alertTime();
            if (BF_FAILURE_RULE_ID.equals(l.ruleId())) {
                recentFailures.addLast(t);
                while (recentFailures.peekFirst().isBefore(t.minus(CorrelationEngine.BF_TIMEFRAME))) {
                    recentFailures.pollFirst();
                }
                if (recentFailures.size() >= CorrelationEngine.BF_FAILURE_THRESHOLD) {
                    lastThreshold = t;
                    if (criterion == null) {
                        criterion = t;
                    }
                }
            } else if (compromise == null && lastThreshold != null
                    && !t.isAfter(lastThreshold.plus(CorrelationEngine.BF_TIMEFRAME))) {
                compromise = t;
            }
        }
        return criterion == null ? Detection.NONE : Detection.at(criterion, compromise);
    }

    /** 스프레이 캠페인 (AN1277): 같은 srcIp 실패 alert 의 서로 다른 username 수 ≥ 임계 */
    private Detection detectSpray(String srcIp, List<DetectionLink> usable) {
        Set<String> accounts = new HashSet<>();
        for (DetectionLink l : usable) {
            if (BF_FAILURE_RULE_ID.equals(l.ruleId()) && l.username() != null && Objects.equals(srcIp, l.srcIp())) {
                accounts.add(l.username());
                if (accounts.size() >= sprayAccountThreshold) {
                    return Detection.at(l.alertTime(), null);
                }
            }
        }
        return Detection.NONE;
    }

    /** 하나라도 SUCCEEDED → SUCCEEDED / 전부 FAILED → FAILED / 그 외 UNKNOWN (T1110.003: 한 계정이라도 뚫리면 성공) */
    private static GroundTruthOutcome aggregate(List<GroundTruthOutcome> outcomes) {
        if (outcomes.contains(GroundTruthOutcome.SUCCEEDED)) {
            return GroundTruthOutcome.SUCCEEDED;
        }
        if (outcomes.stream().allMatch(o -> o == GroundTruthOutcome.FAILED)) {
            return GroundTruthOutcome.FAILED;
        }
        return GroundTruthOutcome.UNKNOWN;
    }

    private static double best(List<DetectionLink> links) {
        return links.stream().mapToDouble(DetectionLink::confidence).max().orElse(0.0);
    }
}
