package com.capstone.vuln.correlation;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Correlation·VerdictResult 를 validation schema 에 저장한다 (한 번의 save = 한 트랜잭션)
 *
 * - correlation: correlation_key 로 upsert, detection_link 는 매번 다시 쓴다(파생 데이터)
 * - verdict_result: unit_key 로 upsert. initial_verdict 는 최초 값을 보존하고,
 *   verdict 가 바뀌면 verdict_history 에 1행 추가 (append-only)
 * - verdict_member: memberCorrelationIds(correlationKey) → correlation PK 로 연결
 * - detection_link.control(S4-4 R14): 링크마다 통제(APP_RULE·NIDS)를 기록한다
 * - telemetry_observation(S4-4 R15): 텔레메트리를 넘긴 save 만 verdict × 센서 1행씩 upsert (verdict 의 run_id 와 같은 run)
 * - run_id·attempt_role(S4-1): 새 verdict INSERT 때만 기록. 갱신(UPDATE) 경로는 건드리지 않아 최초 run 귀속이 유지된다.
 *   CLOSED run 에 대한 INSERT 는 DB 트리거가 거부한다(V2). run_id 는 NOT NULL(V3) — run 없는 저장 경로는 없다.
 * 저장 금지: 비밀번호·요청/응답 본문·Mock IMDS 값 — 이 저장소는 그런 값을 받지도 않는다.
 *
 * 트랜잭션 매니저는 빈으로 등록하지 않는다 (취약 앱의 자동설정 트랜잭션 매니저를 건드리지 않기 위해).
 */
public class VerdictRepository {

    static final String REASON_LATE_ALERT = "LATE_ALERT";
    static final String REASON_RECOMPUTED = "RECOMPUTED";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public VerdictRepository(DataSource validationDataSource) {
        this.jdbc = new JdbcTemplate(validationDataSource);
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(validationDataSource));
    }

    /**
     * @param runId          새 verdict 의 run_id (measurement_run, OPEN) — V3 부터 NOT NULL
     * @param rolesByUnitKey unit_key → 시도 역할, 없으면 ATTACK
     */
    public void save(UUID runId, List<Correlation> correlations, List<VerdictResult> verdicts,
                     Map<String, AttemptRole> rolesByUnitKey) {
        save(runId, correlations, verdicts, rolesByUnitKey, null);
    }

    /**
     * @param telemetryByUnitKey unit_key → 센서별 이벤트 수 (R15). null 이면 텔레메트리를 쓰지 않는다(R14 이전 경로)
     */
    public void save(UUID runId, List<Correlation> correlations, List<VerdictResult> verdicts,
                     Map<String, AttemptRole> rolesByUnitKey,
                     Map<String, Map<TelemetrySensor, Integer>> telemetryByUnitKey) {
        tx.executeWithoutResult(status -> {
            Map<String, Long> correlationIds = new HashMap<>();
            for (Correlation c : correlations) {
                correlationIds.put(c.getCorrelationKey(), upsertCorrelation(c));
            }
            for (VerdictResult v : verdicts) {
                long verdictId = upsertVerdict(v, correlationIds, runId,
                        rolesByUnitKey.getOrDefault(v.unitKey(), AttemptRole.ATTACK));
                if (telemetryByUnitKey != null && telemetryByUnitKey.containsKey(v.unitKey())) {
                    upsertTelemetry(verdictId, telemetryByUnitKey.get(v.unitKey()));
                }
            }
        });
    }

    /** verdict 의 run_id 를 그대로 쓴다 — 갱신 경로(늦은 alert)에서도 최초 run 귀속 유지 */
    private void upsertTelemetry(long verdictId, Map<TelemetrySensor, Integer> sensors) {
        for (Map.Entry<TelemetrySensor, Integer> e : sensors.entrySet()) {
            jdbc.update("""
                    INSERT INTO validation.telemetry_observation (run_id, verdict_id, sensor, event_count)
                    SELECT run_id, id, ?, ? FROM validation.verdict_result WHERE id = ?
                    ON CONFLICT (verdict_id, sensor) DO UPDATE SET event_count = EXCLUDED.event_count""",
                    e.getKey().name(), e.getValue(), verdictId);
        }
    }

    public Optional<VerdictResult> findVerdict(String unitKey) {
        List<Map.Entry<Long, VerdictRow>> rows = jdbc.query(
                "SELECT * FROM validation.verdict_result WHERE unit_key = ?",
                (rs, n) -> Map.entry(rs.getLong("id"), VerdictRow.of(rs)), unitKey);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        List<String> members = jdbc.queryForList("""
                SELECT c.correlation_key FROM validation.verdict_member m
                JOIN validation.correlation c ON c.id = m.correlation_id
                WHERE m.verdict_id = ? ORDER BY c.id""", String.class, rows.get(0).getKey());
        return Optional.of(rows.get(0).getValue().toResult(members));
    }

    private long upsertCorrelation(Correlation c) {
        CorrelationKey key = c.getKey();
        Long id = jdbc.queryForObject("""
                INSERT INTO validation.correlation (correlation_key, op_id, op_id_resolved, paw, ability_id, rid,
                    scenario, technique_id, src_ip, username, segment_id, attack_time, last_attack_time, observed_until,
                    gt_outcome, attacker_verdict, best_confidence, correlation_source, detection_status_raw, mttd_ms_raw,
                    ingestion_lag_ms, bf_failure_count, bf_sequence, spray, spray_account_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (correlation_key) DO UPDATE SET
                    op_id = EXCLUDED.op_id, op_id_resolved = EXCLUDED.op_id_resolved, paw = EXCLUDED.paw,
                    ability_id = EXCLUDED.ability_id, rid = EXCLUDED.rid, scenario = EXCLUDED.scenario,
                    technique_id = EXCLUDED.technique_id, src_ip = EXCLUDED.src_ip, username = EXCLUDED.username,
                    segment_id = EXCLUDED.segment_id, attack_time = EXCLUDED.attack_time,
                    last_attack_time = EXCLUDED.last_attack_time, observed_until = EXCLUDED.observed_until,
                    gt_outcome = EXCLUDED.gt_outcome, attacker_verdict = EXCLUDED.attacker_verdict,
                    best_confidence = EXCLUDED.best_confidence, correlation_source = EXCLUDED.correlation_source,
                    detection_status_raw = EXCLUDED.detection_status_raw, mttd_ms_raw = EXCLUDED.mttd_ms_raw,
                    ingestion_lag_ms = EXCLUDED.ingestion_lag_ms, bf_failure_count = EXCLUDED.bf_failure_count,
                    bf_sequence = EXCLUDED.bf_sequence, spray = EXCLUDED.spray,
                    spray_account_count = EXCLUDED.spray_account_count
                RETURNING id""", Long.class,
                c.getCorrelationKey(),
                key.opIdResolved() ? uuidOrNull(key.opId()) : null,
                key.opIdResolved(),
                key.agentPaw(),
                key.abilityId(),
                key.rid(),
                c.getScenario(),
                c.getTechniqueId(),
                c.getSrcIp(),
                c.getUsername(),
                c.getSegmentId(),
                ts(c.getAttackTime()),
                ts(c.getLastAttackTime()),
                ts(c.getObservedUntil()),
                name(c.getGtOutcome()),
                name(c.getAttackerVerdict()),
                c.getBestConfidence(),
                c.getCorrelationSource().name(),
                name(c.getDetectionStatus()),
                c.getMttdMs(),
                c.getIngestionLagMs(),
                c.getBfFailureCount(),
                c.isBfSequence(),
                c.isSpray(),
                c.getSprayAccountCount());

        jdbc.update("DELETE FROM validation.detection_link WHERE correlation_id = ?", id);
        // alert_ref 는 alert 파서 슬라이스에서 채운다 (현재 AlertEvent 에 원본 alert id 없음)
        jdbc.batchUpdate("""
                INSERT INTO validation.detection_link (correlation_id, rule_id, technique, alert_time, match_path,
                    confidence, src_ip, username, late, alert_ref, control)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)""", c.getLinks(), 100, (ps, l) -> {
            ps.setLong(1, id);
            ps.setString(2, l.ruleId());
            ps.setString(3, l.technique());
            ps.setObject(4, ts(l.alertTime()));
            ps.setString(5, l.matchPath().name());
            ps.setDouble(6, l.confidence());
            ps.setString(7, l.srcIp());
            ps.setString(8, l.username());
            ps.setBoolean(9, l.alertTime().isAfter(c.getObservedUntil()));
            ps.setString(10, l.control().name());
        });
        return id;
    }

    private long upsertVerdict(VerdictResult v, Map<String, Long> correlationIds, UUID runId, AttemptRole role) {
        List<Map<String, Object>> existing = jdbc.queryForList(
                "SELECT id, verdict FROM validation.verdict_result WHERE unit_key = ? FOR UPDATE", v.unitKey());
        long verdictId;
        if (existing.isEmpty()) {
            verdictId = jdbc.queryForObject("""
                    INSERT INTO validation.verdict_result (unit_key, unit_type, scenario, technique_id, verdict,
                        initial_verdict, uncertain_reason, detection_status, gt_outcome, attacker_verdict, attacker_match,
                        overestimate, best_confidence, mttd_ms, late_detection, compromise_detected, compromise_alert_time,
                        spray_account_count, engine_version, run_id, attempt_role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING id""", Long.class,
                    v.unitKey(), v.unitType().name(), v.scenario(), v.techniqueId(), v.verdict().name(),
                    v.initialVerdict().name(), name(v.uncertainReason()), v.detectionStatus().name(),
                    v.gtOutcome().name(), name(v.attackerVerdict()), v.attackerMatch(), v.overestimate(),
                    v.bestConfidence(), v.mttdMs(), v.lateDetection(), v.compromiseDetected(),
                    ts(v.compromiseAlertTime()), v.sprayAccountCount(), VerdictEngine.ENGINE_VERSION,
                    runId, role.name());
            if (v.initialVerdict() != v.verdict()) {
                appendHistory(verdictId, v.initialVerdict(), v.verdict(), REASON_LATE_ALERT);
            }
        } else {
            verdictId = ((Number) existing.get(0).get("id")).longValue();
            Verdict previous = Verdict.valueOf((String) existing.get(0).get("verdict"));
            // initial_verdict 는 최초 저장값을 보존한다
            jdbc.update("""
                    UPDATE validation.verdict_result SET unit_type = ?, scenario = ?, technique_id = ?, verdict = ?,
                        uncertain_reason = ?, detection_status = ?, gt_outcome = ?, attacker_verdict = ?,
                        attacker_match = ?, overestimate = ?, best_confidence = ?, mttd_ms = ?, late_detection = ?,
                        compromise_detected = ?, compromise_alert_time = ?, spray_account_count = ?,
                        engine_version = ?, decided_at = now()
                    WHERE id = ?""",
                    v.unitType().name(), v.scenario(), v.techniqueId(), v.verdict().name(),
                    name(v.uncertainReason()), v.detectionStatus().name(), v.gtOutcome().name(),
                    name(v.attackerVerdict()), v.attackerMatch(), v.overestimate(), v.bestConfidence(),
                    v.mttdMs(), v.lateDetection(), v.compromiseDetected(), ts(v.compromiseAlertTime()),
                    v.sprayAccountCount(), VerdictEngine.ENGINE_VERSION, verdictId);
            if (previous != v.verdict()) {
                appendHistory(verdictId, previous, v.verdict(),
                        v.lateDetection() ? REASON_LATE_ALERT : REASON_RECOMPUTED);
            }
        }

        jdbc.update("DELETE FROM validation.verdict_member WHERE verdict_id = ?", verdictId);
        for (String correlationKey : v.memberCorrelationIds()) {
            Long correlationId = correlationIds.get(correlationKey);
            if (correlationId == null) {
                correlationId = jdbc.queryForObject(
                        "SELECT id FROM validation.correlation WHERE correlation_key = ?", Long.class, correlationKey);
            }
            jdbc.update("INSERT INTO validation.verdict_member (verdict_id, correlation_id) VALUES (?, ?)",
                    verdictId, correlationId);
        }
        return verdictId;
    }

    private void appendHistory(long verdictId, Verdict from, Verdict to, String reason) {
        jdbc.update("INSERT INTO validation.verdict_history (verdict_id, from_verdict, to_verdict, reason) VALUES (?, ?, ?, ?)",
                verdictId, from.name(), to.name(), reason);
    }

    /** DB 행 → VerdictResult (memberCorrelationIds 는 따로 조회해 채운다) */
    private record VerdictRow(UnitType unitType, String unitKey, String scenario, String techniqueId,
                              Verdict verdict, Verdict initialVerdict, UncertainReason uncertainReason,
                              DetectionStatus detectionStatus, GroundTruthOutcome gtOutcome,
                              GroundTruthOutcome attackerVerdict, Boolean attackerMatch, boolean overestimate,
                              double bestConfidence, Long mttdMs, boolean lateDetection, Boolean compromiseDetected,
                              Instant compromiseAlertTime, int sprayAccountCount) {

        static VerdictRow of(ResultSet rs) throws SQLException {
            String uncertain = rs.getString("uncertain_reason");
            String attacker = rs.getString("attacker_verdict");
            OffsetDateTime compromiseAt = rs.getObject("compromise_alert_time", OffsetDateTime.class);
            return new VerdictRow(
                    UnitType.valueOf(rs.getString("unit_type")),
                    rs.getString("unit_key"),
                    rs.getString("scenario"),
                    rs.getString("technique_id"),
                    Verdict.valueOf(rs.getString("verdict")),
                    Verdict.valueOf(rs.getString("initial_verdict")),
                    uncertain == null ? null : UncertainReason.valueOf(uncertain),
                    DetectionStatus.valueOf(rs.getString("detection_status")),
                    GroundTruthOutcome.valueOf(rs.getString("gt_outcome")),
                    attacker == null ? null : GroundTruthOutcome.valueOf(attacker),
                    rs.getObject("attacker_match", Boolean.class),
                    rs.getBoolean("overestimate"),
                    rs.getDouble("best_confidence"),
                    rs.getObject("mttd_ms", Long.class),
                    rs.getBoolean("late_detection"),
                    rs.getObject("compromise_detected", Boolean.class),
                    compromiseAt == null ? null : compromiseAt.toInstant(),
                    rs.getInt("spray_account_count"));
        }

        VerdictResult toResult(List<String> members) {
            return new VerdictResult(unitType, unitKey, scenario, techniqueId, members, verdict, initialVerdict,
                    uncertainReason, detectionStatus, gtOutcome, attackerVerdict, attackerMatch, overestimate,
                    bestConfidence, mttdMs, lateDetection, compromiseDetected, compromiseAlertTime, sprayAccountCount);
        }
    }

    private static OffsetDateTime ts(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }

    private static String name(Enum<?> value) {
        return value == null ? null : value.name();
    }

    /** op_id 컬럼은 uuid — 해석됐더라도 UUID 형식이 아니면 NULL (paw 는 별도 컬럼에 보존) */
    private static UUID uuidOrNull(String value) {
        try {
            return value == null ? null : UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
