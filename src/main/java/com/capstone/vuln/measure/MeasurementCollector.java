package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackOutcome;
import com.capstone.vuln.correlation.AlertEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * op 1개 창의 수집을 묶는다 (수집기 호출만). 판정·상관·저장은 b-2b 범위이므로 하지 않는다.
 *
 * <p>읽기 창(결정 D) = [attackTime(opStart), opFinish + readWindowTail]. runOnce 가 돌려준 finish 를
 * opFinish 로 쓴다. 엔진 내부 per-group 관찰 30초(결정4)는 이 읽기 창과 다른 개념이며 엔진이 따로 적용한다.
 *
 * <p>S4-4 (R14): EveTelemetryReader 가 있으면 Suricata alert(86601)와 eve http 도 읽는다. eve http 는 창 시작
 * HTTP_LOOKBACK 앞부터 읽는다 — alert 는 Wazuh 시각(http 보다 늦음)으로 창에 들므로, 창 경계 직전 요청의 http 를
 * 놓쳐 orphan 으로 세지 않기 위해서다(시도 연결은 Caldera 링크 창이 따로 거른다).
 */
public class MeasurementCollector {

    /** op 완료 후 늦게 쓰인 로그·늦은 alert 를 포함하기 위한 꼬리 시간(기본 30s). */
    public static final Duration DEFAULT_READ_WINDOW_TAIL = Duration.ofSeconds(30);
    /** eve http 를 창 시작보다 앞서 읽는 폭 (R14 b orphan 오검출 방지) */
    public static final Duration HTTP_LOOKBACK = Duration.ofSeconds(30);

    private final GtLogReader gtLogReader;
    private final AlertIndexReader alertIndexReader;
    private final AttackerVerdictResolver attackerVerdictResolver;
    private final Duration readWindowTail;
    private final EveTelemetryReader eveTelemetryReader;

    public MeasurementCollector(GtLogReader gtLogReader,
                                AlertIndexReader alertIndexReader,
                                AttackerVerdictResolver attackerVerdictResolver,
                                Duration readWindowTail) {
        this(gtLogReader, alertIndexReader, attackerVerdictResolver, readWindowTail, null);
    }

    public MeasurementCollector(GtLogReader gtLogReader,
                                AlertIndexReader alertIndexReader,
                                AttackerVerdictResolver attackerVerdictResolver,
                                Duration readWindowTail,
                                EveTelemetryReader eveTelemetryReader) {
        this.gtLogReader = gtLogReader;
        this.alertIndexReader = alertIndexReader;
        this.attackerVerdictResolver = attackerVerdictResolver;
        this.readWindowTail = readWindowTail;
        this.eveTelemetryReader = eveTelemetryReader;
    }

    public Duration readWindowTail() {
        return readWindowTail;
    }

    public CollectedWindow collect(String opId, Instant attackTime, Instant opFinish) {
        Instant windowEnd = opFinish.plus(readWindowTail);
        GtLogReader.GtWindow gt = gtLogReader.readWindow(attackTime, windowEnd);
        List<AlertEvent> alerts = alertIndexReader.read(attackTime, windowEnd);
        Map<PawAbility, AttackOutcome> attackerVerdicts = attackerVerdictResolver.resolve(opId);
        if (eveTelemetryReader == null) {
            return new CollectedWindow(gt.events(), alerts, attackerVerdicts, gt.roles());
        }
        List<NidsAlert> nidsAlerts = alertIndexReader.readNids(attackTime, windowEnd);
        List<EveHttp> http = eveTelemetryReader.read(attackTime.minus(HTTP_LOOKBACK), windowEnd);
        return new CollectedWindow(gt.events(), alerts, attackerVerdicts, gt.roles(), nidsAlerts, http, gt.args());
    }
}
