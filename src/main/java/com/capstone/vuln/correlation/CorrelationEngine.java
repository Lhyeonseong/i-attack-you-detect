package com.capstone.vuln.correlation;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 공격 이벤트 ↔ 탐지 알림 시간창 상관 엔진 (순수 로직)
 *
 * - 관찰기간: attackTime ≤ alertTime ≤ observedUntil(마지막 이벤트 + 30s)
 * - 매칭 경로(강→약): rid 일치 RID / op_id+ability_id 일치 HEADER(UA 로 복구됐으면 UA_FALLBACK)
 *   / 식별자(rid·op) 없는 alert 가 같은 엔드포인트·srcIp·관찰기간이면 TIME_ONLY
 *   / NIDS alert(S4-4 R14 c)는 하네스가 정한 시도 rid 의 그룹에만 UA_FALLBACK — 다른 경로로는 엮지 않는다
 * - alert 1건은 가장 강하게 매칭되는 Correlation 1건에만 링크한다
 * - BF(T1110): srcIp 1차 + username 하위로 묶고, 처리 순서가 아니라 이벤트 time 기준으로
 *   "실패 반복 후 성공"을 판정한다 (Wazuh 100231/100233 대체, Gap#1)
 *   · AN1275(계정 반복 실패)·AN1276(실패 후 성공): 같은 srcIp+username 시퀀스
 *   · AN1277(스프레이): 같은 srcIp 가 여러 username 에 시도 → spray 플래그
 *   op_id/ability_id 는 묶는 키가 아니라 라벨이다. op 로 묶으면 op 교체·스프레이 때 쪼개져 Gap#1 이 재발한다.
 *   마지막 실패 후 BF_TIMEFRAME 넘는 공백이면 새 시퀀스 (Sigma temporal timespan)
 */
public class CorrelationEngine {

    static final String BRUTE_FORCE_TECHNIQUE = "T1110";
    /** Wazuh 100231 frequency="10" timeframe="120" 과 동일 기준 */
    static final int BF_FAILURE_THRESHOLD = 10;
    static final Duration BF_TIMEFRAME = Duration.ofSeconds(120);
    /**
     * 같은 srcIp 의 한 시퀀스 구간에서 실패한 서로 다른 계정 수가 이 이상이면 스프레이.
     * AN1277 조정값 — 표준 수치 없음, 잠정. 설정값 app.correlation.spray-account-threshold 로 바꿀 수 있다
     */
    public static final int DEFAULT_SPRAY_ACCOUNT_THRESHOLD = 5;

    /** observedUntil 이후 이 시간까지만 늦은 alert 로 연결. null = 상한 없음 (CorrelationConfig 참조) */
    private final Duration lateAlertCap;
    private final int sprayAccountThreshold;

    public CorrelationEngine() {
        this(null);
    }

    public CorrelationEngine(Duration lateAlertCap) {
        this(lateAlertCap, DEFAULT_SPRAY_ACCOUNT_THRESHOLD);
    }

    public CorrelationEngine(Duration lateAlertCap, int sprayAccountThreshold) {
        this.lateAlertCap = lateAlertCap;
        this.sprayAccountThreshold = sprayAccountThreshold;
    }

    /** 같은 시각이면 실패를 먼저 센다 ("실패 반복 후 성공") */
    private static final Comparator<AttackEvent> BY_TIME = Comparator
            .comparing(AttackEvent::attackTime)
            .thenComparing(e -> e.gtOutcome() != GroundTruthOutcome.FAILED);

    private static final Comparator<Match> STRONGEST = Comparator
            .comparingDouble((Match m) -> Confidence.of(m.path()).value())
            .thenComparing(Match::inWindow)
            .thenComparing(m -> m.group().first().attackTime());

    /** alert 의 op_id(paw)·ability_id 와 비교하는 원본 식별자 쌍 */
    private record PawAbility(String paw, String abilityId) {
    }

    /** segmentId: BF 그룹이 속한 srcIp 시퀀스 구간 (스프레이 캠페인 묶기용). 단건이면 null */
    private record Group(List<AttackEvent> events, Set<String> rids, Set<PawAbility> ids,
                         String segmentId, boolean spray, int sprayAccountCount) {

        static Group of(List<AttackEvent> sortedEvents, String segmentId, boolean spray, int sprayAccountCount) {
            Set<String> rids = sortedEvents.stream()
                    .map(e -> e.key().rid())
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
            Set<PawAbility> ids = sortedEvents.stream()
                    .map(e -> new PawAbility(e.key().agentPaw(), e.key().abilityId()))
                    .collect(Collectors.toSet());
            return new Group(sortedEvents, rids, ids, segmentId, spray, sprayAccountCount);
        }

        AttackEvent first() { return events.get(0); }
        AttackEvent last() { return events.get(events.size() - 1); }
        Instant observedUntil() { return last().attackTime().plus(Correlation.OBSERVATION_WINDOW); }
    }

    private record Match(Group group, AlertEvent alert, MatchPath path, boolean inWindow) {
    }

    public List<Correlation> correlate(List<AttackEvent> attacks, List<AlertEvent> alerts) {
        List<Group> groups = group(attacks);

        Map<Group, List<Match>> matchesByGroup = new IdentityHashMap<>();
        for (AlertEvent alert : alerts) {
            groups.stream()
                    .map(g -> match(g, alert))
                    .filter(Objects::nonNull)
                    .max(STRONGEST)
                    .ifPresent(m -> matchesByGroup.computeIfAbsent(m.group(), g -> new ArrayList<>()).add(m));
        }

        return groups.stream()
                .map(g -> build(g, matchesByGroup.getOrDefault(g, List.of())))
                .toList();
    }

    private List<Group> group(List<AttackEvent> attacks) {
        List<Group> groups = new ArrayList<>();
        Map<String, List<AttackEvent>> bruteForceByIp = new LinkedHashMap<>();
        for (AttackEvent e : attacks) {
            if (BRUTE_FORCE_TECHNIQUE.equals(e.techniqueId())) {
                bruteForceByIp.computeIfAbsent(e.srcIp(), ip -> new ArrayList<>()).add(e);
            } else {
                groups.add(Group.of(List.of(e), null, false, 0));
            }
        }
        bruteForceByIp.values().forEach(events -> groups.addAll(bruteForceGroups(events)));
        groups.sort(Comparator.comparing(g -> g.first().attackTime()));
        return groups;
    }

    /** 같은 srcIp 의 BF 이벤트 → 시간 분할 → 구간별 스프레이 판정 → username 별(다시 시간 분할) 그룹 */
    private List<Group> bruteForceGroups(List<AttackEvent> ipEvents) {
        List<Group> groups = new ArrayList<>();
        for (List<AttackEvent> ipSegment : splitByGap(ipEvents.stream().sorted(BY_TIME).toList())) {
            int failedAccounts = (int) ipSegment.stream()
                    .filter(e -> e.gtOutcome() == GroundTruthOutcome.FAILED)
                    .map(AttackEvent::username)
                    .distinct()
                    .count();
            boolean spray = failedAccounts >= sprayAccountThreshold;
            String segmentId = ipSegment.get(0).srcIp() + "#" + ipSegment.get(0).attackTime().toEpochMilli();

            Map<String, List<AttackEvent>> byUser = new LinkedHashMap<>();
            ipSegment.forEach(e -> byUser.computeIfAbsent(e.username(), u -> new ArrayList<>()).add(e));
            for (List<AttackEvent> userEvents : byUser.values()) {
                for (List<AttackEvent> sequence : splitByGap(userEvents)) {
                    groups.add(Group.of(sequence, segmentId, spray, spray ? failedAccounts : 0));
                }
            }
        }
        return groups;
    }

    /** 시각순 이벤트를 마지막 실패(실패가 없으면 마지막 이벤트) 후 BF_TIMEFRAME 넘는 공백에서 자른다 */
    private static List<List<AttackEvent>> splitByGap(List<AttackEvent> sortedEvents) {
        List<List<AttackEvent>> segments = new ArrayList<>();
        List<AttackEvent> current = new ArrayList<>();
        Instant lastFailure = null;
        Instant lastEvent = null;
        for (AttackEvent e : sortedEvents) {
            Instant reference = lastFailure != null ? lastFailure : lastEvent;
            if (reference != null && Duration.between(reference, e.attackTime()).compareTo(BF_TIMEFRAME) > 0) {
                segments.add(current);
                current = new ArrayList<>();
                lastFailure = null;
            }
            current.add(e);
            lastEvent = e.attackTime();
            if (e.gtOutcome() == GroundTruthOutcome.FAILED) {
                lastFailure = e.attackTime();
            }
        }
        if (!current.isEmpty()) {
            segments.add(current);
        }
        return segments;
    }

    private Match match(Group group, AlertEvent alert) {
        AttackEvent first = group.first();
        if (alert.alertTime().isBefore(first.attackTime())) {
            return null;
        }
        boolean inWindow = !alert.alertTime().isAfter(group.observedUntil());
        if (!inWindow && lateAlertCap != null
                && alert.alertTime().isAfter(group.observedUntil().plus(lateAlertCap))) {
            return null;
        }

        // NIDS(R14 c): rid 는 eve http → 시도 연결로 정한 값 — 그 시도의 그룹에만, UA_FALLBACK(0.7) 으로 연결한다
        if (alert.control() == DetectionControl.NIDS) {
            return alert.rid() != null && group.rids().contains(alert.rid())
                    ? new Match(group, alert, MatchPath.UA_FALLBACK, inWindow)
                    : null;
        }
        if (alert.rid() != null && group.rids().contains(alert.rid())) {
            return new Match(group, alert, MatchPath.RID, inWindow);
        }
        // alert 의 op_id 는 로그 원본(paw) 이므로 UUID 가 아니라 agentPaw 와 비교한다
        if (alert.opId() != null && alert.abilityId() != null
                && group.ids().contains(new PawAbility(alert.opId(), alert.abilityId()))) {
            MatchPath path = alert.idSource() == CorrelationSource.UA_FALLBACK
                    ? MatchPath.UA_FALLBACK
                    : MatchPath.HEADER;
            return new Match(group, alert, path, inWindow);
        }
        // 식별자를 가진 alert 는 다른 공격의 것이므로 시간창만으로 엮지 않는다
        boolean anonymous = alert.rid() == null && alert.opId() == null;
        if (anonymous && inWindow
                && Objects.equals(alert.endpoint(), first.endpoint())
                && Objects.equals(alert.srcIp(), first.srcIp())) {
            return new Match(group, alert, MatchPath.TIME_ONLY, true);
        }
        return null;
    }

    private static Correlation build(Group group, List<Match> matches) {
        AttackEvent first = group.first();
        CorrelationKey label = representativeKey(group.events());
        Correlation c = new Correlation(
                new CorrelationKey(label.opId(), label.agentPaw(), label.abilityId(),
                        first.key().rid(), label.opIdResolved()),
                first.scenario(), first.techniqueId(),
                first.attackTime(), group.last().attackTime(), first.srcIp());
        c.setUsername(first.username());
        c.setSegmentId(group.segmentId());
        c.setSpray(group.spray());
        c.setSprayAccountCount(group.sprayAccountCount());
        c.setEventCount(group.events().size());
        c.setEventRids(group.events().stream().map(e -> e.key().rid()).filter(Objects::nonNull).toList());
        c.setGtOutcome(aggregateOutcome(group.events()));
        if (BRUTE_FORCE_TECHNIQUE.equals(first.techniqueId())) {
            applyBruteForceSequence(c, group.events());
        }

        List<Match> byAlertTime = matches.stream()
                .sorted(Comparator.comparing(m -> m.alert().alertTime()))
                .toList();
        for (Match m : byAlertTime) {
            AlertEvent a = m.alert();
            c.addLink(DetectionLink.of(a, m.path()));
        }
        c.setLateDetection(byAlertTime.stream().anyMatch(m -> !m.inWindow()));

        // MTTD/DETECTED 는 관찰기간 내 usable(≥0.7) alert 만으로 산출
        byAlertTime.stream()
                .filter(m -> m.inWindow() && Confidence.of(m.path()).usableForVerdict())
                .findFirst()
                .ifPresentOrElse(earliest -> {
                    AlertEvent a = earliest.alert();
                    c.setDetectionStatus(DetectionStatus.DETECTED);
                    c.setMttdMs(Duration.between(c.getAttackTime(), a.alertTime()).toMillis());
                    if (a.searchableTime() != null) {
                        c.setIngestionLagMs(Duration.between(a.alertTime(), a.searchableTime()).toMillis());
                    }
                }, () -> c.setDetectionStatus(DetectionStatus.NOT_DETECTED));
        return c;
    }

    /** 그룹 라벨(op/ability): 성공 이벤트의 것, 없으면 최빈값 (동률이면 먼저 나온 것). rid 는 무시 */
    private static CorrelationKey representativeKey(List<AttackEvent> sortedEvents) {
        return sortedEvents.stream()
                .filter(e -> e.gtOutcome() == GroundTruthOutcome.SUCCEEDED)
                .findFirst()
                .map(AttackEvent::key)
                .orElseGet(() -> sortedEvents.stream()
                        .map(e -> new CorrelationKey(e.key().opId(), e.key().agentPaw(), e.key().abilityId(),
                                null, e.key().opIdResolved()))
                        .collect(Collectors.groupingBy(k -> k, LinkedHashMap::new, Collectors.counting()))
                        .entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .orElseThrow()
                        .getKey());
    }

    private static GroundTruthOutcome aggregateOutcome(List<AttackEvent> events) {
        if (events.stream().anyMatch(e -> e.gtOutcome() == GroundTruthOutcome.SUCCEEDED)) {
            return GroundTruthOutcome.SUCCEEDED;
        }
        if (events.stream().allMatch(e -> e.gtOutcome() == GroundTruthOutcome.FAILED)) {
            return GroundTruthOutcome.FAILED;
        }
        return GroundTruthOutcome.UNKNOWN;
    }

    /**
     * 시각순 이벤트에서 120s 창 내 실패 ≥ 10 (임계 도달 시각 = 그 실패의 time) 뒤
     * 120s 안에 성공이 오면 시퀀스 성립. 도착 순서와 무관하다.
     */
    private static void applyBruteForceSequence(Correlation c, List<AttackEvent> sortedEvents) {
        Deque<Instant> recentFailures = new ArrayDeque<>();
        Instant thresholdReachedAt = null;
        int failures = 0;
        boolean sequence = false;
        for (AttackEvent e : sortedEvents) {
            Instant t = e.attackTime();
            if (e.gtOutcome() == GroundTruthOutcome.FAILED) {
                failures++;
                recentFailures.addLast(t);
                while (recentFailures.peekFirst().isBefore(t.minus(BF_TIMEFRAME))) {
                    recentFailures.pollFirst();
                }
                if (recentFailures.size() >= BF_FAILURE_THRESHOLD) {
                    thresholdReachedAt = t;
                }
            } else if (e.gtOutcome() == GroundTruthOutcome.SUCCEEDED
                    && thresholdReachedAt != null
                    && !t.isAfter(thresholdReachedAt.plus(BF_TIMEFRAME))) {
                sequence = true;
            }
        }
        c.setBfFailureCount(failures);
        c.setBfSequence(sequence);
    }
}
