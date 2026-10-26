package com.capstone.vuln.correlation;

import com.capstone.vuln.attack.AttackOutcome;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 공격 1건 ↔ 탐지 알림 상관분석 결과 (S3 소비 계층)
 *
 * detectionStatus·mttdMs·lateDetection 은 링크 기반 원시값(S3-2 의미 — 관찰기간 내 usable 링크 유무)으로
 * 디버깅·Gap 분석용이다. 시나리오 탐지 기준 판정값은 VerdictResult 에 있고 S4 지표는 그쪽만 쓴다.
 *
 * 식별자는 생성 시 고정하고, Ground Truth·공격자 판정·탐지·지표·verdict 는
 * 수집/엔진 단계에서 채워 나간다.
 */
public class Correlation {

    public static final Duration OBSERVATION_WINDOW = Duration.ofSeconds(30);

    // 식별자
    private final CorrelationKey key;
    private final String scenario;
    private final String techniqueId;
    private final Instant attackTime;
    private final String srcIp;
    /** 묶인 이벤트 중 가장 늦은 시각 (단건이면 attackTime) */
    private final Instant lastAttackTime;
    private final Instant observedUntil;

    // 묶인 이벤트 (BF 시퀀스는 여러 건, 그 외 1건)
    private int eventCount = 1;
    /** 묶인 이벤트들의 rid (rid 없는 이벤트 제외) — 시도별 텔레메트리 집계용(R15) */
    private List<String> eventRids = List.of();
    private int bfFailureCount;
    /** 실패 반복 후 성공 성립 (Wazuh 100233 대체) */
    private boolean bfSequence;
    /** BF 그룹 하위 키 (srcIp 1차 + username) */
    private String username;
    /** BF 그룹이 속한 srcIp 시퀀스 구간 식별자 (스프레이 캠페인 묶기용, 단건이면 null) */
    private String segmentId;
    /** 같은 srcIp 가 여러 계정에 시도 (AN1277 스프레이) */
    private boolean spray;
    private int sprayAccountCount;

    // Ground Truth
    private GroundTruthOutcome gtOutcome;

    // 공격자 측 판정 (Caldera fact: SUCCEEDED/FAILED/EXECUTED/UNKNOWN)
    private AttackOutcome attackerVerdict;

    // 탐지
    private DetectionStatus detectionStatus;
    private final List<DetectionLink> links = new ArrayList<>();

    // 지표
    private double bestConfidence;
    private MatchSource correlationSource = MatchSource.NONE;
    /** null = 미탐 */
    private Long mttdMs;
    private Long ingestionLagMs;
    private boolean lateDetection;

    private Verdict verdict;

    public Correlation(CorrelationKey key, String scenario, String techniqueId,
                       Instant attackTime, String srcIp) {
        this(key, scenario, techniqueId, attackTime, attackTime, srcIp);
    }

    /** 여러 이벤트를 묶은 경우: 관찰기간은 마지막 이벤트 + 30s 까지 */
    public Correlation(CorrelationKey key, String scenario, String techniqueId,
                       Instant attackTime, Instant lastAttackTime, String srcIp) {
        this.key = key;
        this.scenario = scenario;
        this.techniqueId = techniqueId;
        this.attackTime = attackTime;
        this.lastAttackTime = lastAttackTime;
        this.srcIp = srcIp;
        this.observedUntil = lastAttackTime.plus(OBSERVATION_WINDOW);
    }

    public CorrelationKey getKey() { return key; }
    public String getScenario() { return scenario; }
    public String getTechniqueId() { return techniqueId; }
    public Instant getAttackTime() { return attackTime; }
    public String getSrcIp() { return srcIp; }
    public Instant getLastAttackTime() { return lastAttackTime; }
    public Instant getObservedUntil() { return observedUntil; }

    public int getEventCount() { return eventCount; }
    public void setEventCount(int eventCount) { this.eventCount = eventCount; }

    public List<String> getEventRids() { return eventRids; }
    public void setEventRids(List<String> eventRids) { this.eventRids = List.copyOf(eventRids); }

    public int getBfFailureCount() { return bfFailureCount; }
    public void setBfFailureCount(int bfFailureCount) { this.bfFailureCount = bfFailureCount; }

    public boolean isBfSequence() { return bfSequence; }
    public void setBfSequence(boolean bfSequence) { this.bfSequence = bfSequence; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getSegmentId() { return segmentId; }
    public void setSegmentId(String segmentId) { this.segmentId = segmentId; }

    public boolean isSpray() { return spray; }
    public void setSpray(boolean spray) { this.spray = spray; }

    public int getSprayAccountCount() { return sprayAccountCount; }
    public void setSprayAccountCount(int sprayAccountCount) { this.sprayAccountCount = sprayAccountCount; }

    /** Caldera operation UUID (해석 실패 시 paw) */
    public String getOpId() { return key.opId(); }
    public String getAgentPaw() { return key.agentPaw(); }
    public boolean isOpIdResolved() { return key.opIdResolved(); }

    public GroundTruthOutcome getGtOutcome() { return gtOutcome; }
    public void setGtOutcome(GroundTruthOutcome gtOutcome) { this.gtOutcome = gtOutcome; }

    public AttackOutcome getAttackerVerdict() { return attackerVerdict; }
    public void setAttackerVerdict(AttackOutcome attackerVerdict) { this.attackerVerdict = attackerVerdict; }


    public DetectionStatus getDetectionStatus() { return detectionStatus; }
    public void setDetectionStatus(DetectionStatus detectionStatus) { this.detectionStatus = detectionStatus; }

    public List<DetectionLink> getLinks() { return Collections.unmodifiableList(links); }

    /** 링크를 추가하고 bestConfidence·correlationSource 를 다시 산출한다 */
    public void addLink(DetectionLink link) {
        links.add(link);
        ConfidenceResolver.Resolution r = ConfidenceResolver.resolve(links);
        this.bestConfidence = r.bestConfidence();
        this.correlationSource = r.source();
    }

    public double getBestConfidence() { return bestConfidence; }
    public MatchSource getCorrelationSource() { return correlationSource; }

    public Long getMttdMs() { return mttdMs; }
    public void setMttdMs(Long mttdMs) { this.mttdMs = mttdMs; }

    public Long getIngestionLagMs() { return ingestionLagMs; }
    public void setIngestionLagMs(Long ingestionLagMs) { this.ingestionLagMs = ingestionLagMs; }

    public boolean isLateDetection() { return lateDetection; }
    public void setLateDetection(boolean lateDetection) { this.lateDetection = lateDetection; }

    /** @deprecated 판정은 VerdictResult 사용 (VerdictEngine 은 이 필드를 채우지 않는다) */
    @Deprecated
    public Verdict getVerdict() { return verdict; }
    /** @deprecated 판정은 VerdictResult 사용 */
    @Deprecated
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }

    /**
     * 영속화 키 (validation.correlation.correlation_key) — 가장 이른 이벤트 rid,
     * rid 가 없으면 scenario|srcIp|attackTime(epoch ms)
     */
    public String getCorrelationKey() {
        if (key.rid() != null) {
            return key.rid();
        }
        return scenario + "|" + srcIp + "|" + attackTime.toEpochMilli();
    }
}
