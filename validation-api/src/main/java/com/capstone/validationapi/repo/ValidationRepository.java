package com.capstone.validationapi.repo;

import com.capstone.validationapi.dto.ApiDtos.AlertLink;
import com.capstone.validationapi.dto.ApiDtos.Attacker;
import com.capstone.validationapi.dto.ApiDtos.Attempt;
import com.capstone.validationapi.dto.ApiDtos.CompareRow;
import com.capstone.validationapi.dto.ApiDtos.Correlation;
import com.capstone.validationapi.dto.ApiDtos.H2;
import com.capstone.validationapi.dto.ApiDtos.Mttd;
import com.capstone.validationapi.dto.ApiDtos.Provenance;
import com.capstone.validationapi.dto.ApiDtos.Rate;
import com.capstone.validationapi.dto.ApiDtos.Run;
import com.capstone.validationapi.dto.ApiDtos.Snapshot;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * ADR-S4-02 D1·D4: validation_ro 로 공개 뷰·스냅샷·출처를 읽는다. 바인딩 파라미터만(CWE-89).
 * 구간·차이는 뷰/함수 값 그대로 전달하고 재계산하지 않는다. 모든 메서드 읽기 전용 트랜잭션.
 */
@Repository
@Transactional(readOnly = true)
public class ValidationRepository {

    private final JdbcClient db;

    public ValidationRepository(JdbcClient db) {
        this.db = db;
    }

    // ── meta ────────────────────────────────────────────────────────────────
    public List<String> definitionVersions() {
        return db.sql("""
                SELECT DISTINCT s.definition_version
                FROM validation.metric_snapshot s
                WHERE NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = s.run_id AND w.definition_version = s.definition_version)
                ORDER BY 1""").query(String.class).list();
    }

    public int runCount() {
        return db.sql("SELECT count(*) FROM validation.measurement_run").query(Integer.class).single();
    }

    // ── runs ────────────────────────────────────────────────────────────────
    public List<Run> runs() {
        return db.sql("""
                SELECT r.run_id, r.label, r.kind, r.status, r.started_at, r.ended_at, r.git_commit, r.git_dirty,
                       r.expected_attempts, r.expected_controls, i.r10_status AS integrity_status
                FROM validation.measurement_run r
                LEFT JOIN validation.v_run_integrity i ON i.run_id = r.run_id
                ORDER BY r.started_at""")
                .query((rs, n) -> runRow(rs, null, null)).list();
    }

    public Run findRun(UUID runId) {
        List<Run> base = db.sql("""
                SELECT r.run_id, r.label, r.kind, r.status, r.started_at, r.ended_at, r.git_commit, r.git_dirty,
                       r.expected_attempts, r.expected_controls, i.r10_status AS integrity_status
                FROM validation.measurement_run r
                LEFT JOIN validation.v_run_integrity i ON i.run_id = r.run_id
                WHERE r.run_id = :id""")
                .param("id", runId)
                .query((rs, n) -> runRow(rs, runDefinitionVersions(runId), provenance(runId))).list();
        return base.isEmpty() ? null : base.get(0);
    }

    public String integrityStatus(UUID runId) {
        List<String> s = db.sql("SELECT r10_status FROM validation.v_run_integrity WHERE run_id = :id")
                .param("id", runId).query(String.class).list();
        return s.isEmpty() ? null : s.get(0);
    }

    public List<String> runDefinitionVersions(UUID runId) {
        return db.sql("""
                SELECT DISTINCT s.definition_version FROM validation.metric_snapshot s
                WHERE s.run_id = :id
                  AND NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = s.run_id AND w.definition_version = s.definition_version)
                ORDER BY 1""").param("id", runId).query(String.class).list();
    }

    public List<Provenance> provenance(UUID runId) {
        return db.sql("""
                SELECT item, value, source_file, source_line
                FROM validation.run_provenance_note WHERE run_id = :id
                ORDER BY item""").param("id", runId)
                .query((rs, n) -> new Provenance(rs.getString("item"), rs.getString("value"),
                        rs.getString("source_file"), (Integer) rs.getObject("source_line"))).list();
    }

    private Run runRow(ResultSet rs, List<String> defs, List<Provenance> prov) throws SQLException {
        return new Run(rs.getString("run_id"), rs.getString("label"), rs.getString("kind"),
                rs.getString("status"), odt(rs, "started_at"), odt(rs, "ended_at"),
                rs.getString("git_commit"), (Boolean) rs.getObject("git_dirty"),
                rs.getString("integrity_status"),
                (Integer) rs.getObject("expected_attempts"), (Integer) rs.getObject("expected_controls"),
                defs, prov);
    }

    // ── snapshot(확정) ────────────────────────────────────────────────────────
    // "최신 정의"는 문자열 max 가 아니라 가장 최근 저장 시각(snapshot_at) 기준(v1.10 < v1.9 문자 비교 버그 회피).
    public String latestDefinitionVersion() {
        List<String> v = db.sql("""
                SELECT s.definition_version FROM validation.metric_snapshot s
                WHERE NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = s.run_id AND w.definition_version = s.definition_version)
                ORDER BY s.snapshot_at DESC NULLS LAST LIMIT 1""").query(String.class).list();
        return v.isEmpty() ? null : v.get(0);
    }

    public String latestDefinitionVersionForRun(UUID runId) {
        List<String> v = db.sql("""
                SELECT s.definition_version FROM validation.metric_snapshot s
                WHERE s.run_id = :id
                  AND NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = s.run_id AND w.definition_version = s.definition_version)
                ORDER BY s.snapshot_at DESC NULLS LAST LIMIT 1""")
                .param("id", runId).query(String.class).list();
        return v.isEmpty() ? null : v.get(0);
    }

    public List<Snapshot> snapshot(String definitionVersion, UUID runId) {
        return db.sql("""
                SELECT s.metric_id, s.scope_kind, s.scope_key, s.numerator, s.denominator,
                       s.point_estimate, s.ci_lower, s.ci_upper, s.p50_ms, s.p95_ms, s.status,
                       s.definition_version, s.snapshot_rule_version
                FROM validation.metric_snapshot s
                WHERE s.definition_version = :dv
                  AND (:rid::uuid IS NULL OR s.run_id = :rid)
                  AND NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = s.run_id AND w.definition_version = s.definition_version)
                ORDER BY s.run_id, s.metric_id, s.scope_kind, s.scope_key""")
                .param("dv", definitionVersion)
                .param("rid", runId)
                .query((rs, n) -> {
                    long nn = rs.getLong("denominator");
                    boolean zero = rs.wasNull() || nn == 0;
                    return new Snapshot(rs.getString("metric_id"), rs.getString("scope_kind"),
                            rs.getString("scope_key"), lng(rs, "numerator"), lng(rs, "denominator"),
                            zero ? null : dbl(rs, "point_estimate"), zero ? null : dbl(rs, "ci_lower"),
                            zero ? null : dbl(rs, "ci_upper"), dbl(rs, "p50_ms"), dbl(rs, "p95_ms"),
                            rs.getString("status"), rs.getString("definition_version"),
                            rs.getString("snapshot_rule_version"));
                }).list();
    }

    // ── live 지표 뷰 ───────────────────────────────────────────────────────────
    public List<Rate> rates(UUID runId) {
        return db.sql("""
                SELECT metric_id, split_kind, split_unit, x, n, p, lo, hi, status, definition_version
                FROM validation.v_metric_rates WHERE run_id = :id
                ORDER BY metric_id, split_kind, split_unit""")
                .param("id", runId).query((rs, i) -> rateRow(rs)).list();
    }

    public List<Rate> coverage(UUID runId) {
        return db.sql("""
                SELECT metric_id, split_kind, NULL::text AS split_unit, x, n, p, lo, hi, status, definition_version
                FROM validation.v_metric_coverage WHERE run_id = :id
                ORDER BY metric_id, split_kind""")
                .param("id", runId).query((rs, i) -> rateRow(rs)).list();
    }

    public List<Correlation> correlation(UUID runId) {
        return db.sql("""
                SELECT split_kind, split_unit, source, x, n, p, lo, hi, status, definition_version
                FROM validation.v_metric_correlation WHERE run_id = :id
                ORDER BY split_kind, split_unit, source""")
                .param("id", runId).query((rs, i) -> {
                    boolean zero = isZeroN(rs, "n");
                    return new Correlation(rs.getString("split_kind"), rs.getString("split_unit"),
                            rs.getString("source"), lng(rs, "x"), lng(rs, "n"),
                            zero ? null : dbl(rs, "p"), zero ? null : dbl(rs, "lo"), zero ? null : dbl(rs, "hi"),
                            rs.getString("status"), rs.getString("definition_version"));
                }).list();
    }

    public List<Attacker> attacker(UUID runId) {
        return db.sql("""
                SELECT split_kind, split_unit, x, n, p, lo, hi, overestimate, uncertain, criteria_met, status,
                       definition_version
                FROM validation.v_metric_attacker WHERE run_id = :id
                ORDER BY split_kind, split_unit""")
                .param("id", runId).query((rs, i) -> {
                    boolean zero = isZeroN(rs, "n");
                    return new Attacker(rs.getString("split_kind"), rs.getString("split_unit"),
                            lng(rs, "x"), lng(rs, "n"), zero ? null : dbl(rs, "p"),
                            zero ? null : dbl(rs, "lo"), zero ? null : dbl(rs, "hi"),
                            lng(rs, "overestimate"), lng(rs, "uncertain"),
                            (Boolean) rs.getObject("criteria_met"), rs.getString("status"),
                            rs.getString("definition_version"));
                }).list();
    }

    public List<Mttd> mttd(UUID runId) {
        return db.sql("""
                SELECT split_kind, split_unit, n, p50_ms, p95_ms, status, definition_version
                FROM validation.v_metric_mttd WHERE run_id = :id
                ORDER BY split_kind, split_unit""")
                .param("id", runId).query((rs, i) -> {
                    boolean zero = isZeroN(rs, "n");
                    return new Mttd(rs.getString("split_kind"), rs.getString("split_unit"), lng(rs, "n"),
                            zero ? null : dbl(rs, "p50_ms"), zero ? null : dbl(rs, "p95_ms"),
                            rs.getString("status"), rs.getString("definition_version"));
                }).list();
    }

    public H2 h2(UUID runId) {
        List<H2> rows = db.sql("""
                SELECT n, rid_header_x, rid_header_p, rid_header_lo, rid_header_hi,
                       none_x, none_p, none_lo, none_hi, h2_status, definition_version
                FROM validation.v_metric_h2 WHERE run_id = :id""")
                .param("id", runId).query((rs, i) -> {
                    boolean zero = isZeroN(rs, "n");
                    return new H2(lng(rs, "n"), lng(rs, "rid_header_x"),
                            zero ? null : dbl(rs, "rid_header_p"), zero ? null : dbl(rs, "rid_header_lo"),
                            zero ? null : dbl(rs, "rid_header_hi"), lng(rs, "none_x"),
                            zero ? null : dbl(rs, "none_p"), zero ? null : dbl(rs, "none_lo"),
                            zero ? null : dbl(rs, "none_hi"), rs.getString("h2_status"),
                            rs.getString("definition_version"));
                }).list();
        return rows.isEmpty() ? null : rows.get(0);
    }

    private Rate rateRow(ResultSet rs) throws SQLException {
        boolean zero = isZeroN(rs, "n");
        return new Rate(rs.getString("metric_id"), rs.getString("split_kind"), rs.getString("split_unit"),
                lng(rs, "x"), lng(rs, "n"), zero ? null : dbl(rs, "p"),
                zero ? null : dbl(rs, "lo"), zero ? null : dbl(rs, "hi"),
                rs.getString("status"), rs.getString("definition_version"));
    }

    // ── 시도·경보 ──────────────────────────────────────────────────────────────
    public List<Attempt> attempts(UUID runId, String verdict, int limit) {
        return db.sql("""
                SELECT attempt_id, unit_key, scenario, technique_id, attempt_role, gt_outcome, attacker_verdict,
                       attacker_match, verdict, initial_verdict, detection_status, mttd_ms, best_confidence,
                       late_detection, engine_version, decided_at, op_id, rid, ability_id, attack_time,
                       correlation_source
                FROM validation.v_api_attempt
                WHERE run_id = :id AND (:verdict::text IS NULL OR verdict = :verdict)
                ORDER BY scenario, attempt_role, attempt_id
                LIMIT :lim""")
                .param("id", runId).param("verdict", verdict).param("lim", limit)
                .query((rs, i) -> new Attempt(lng(rs, "attempt_id"), rs.getString("unit_key"),
                        rs.getString("scenario"), rs.getString("technique_id"), rs.getString("attempt_role"),
                        rs.getString("gt_outcome"), rs.getString("attacker_verdict"),
                        (Boolean) rs.getObject("attacker_match"), rs.getString("verdict"),
                        rs.getString("initial_verdict"), rs.getString("detection_status"), lng(rs, "mttd_ms"),
                        dbl(rs, "best_confidence"), (Boolean) rs.getObject("late_detection"),
                        rs.getString("engine_version"), odt(rs, "decided_at"), rs.getString("op_id"),
                        rs.getString("rid"), rs.getString("ability_id"), odt(rs, "attack_time"),
                        rs.getString("correlation_source"))).list();
    }

    public List<AlertLink> alertLinks(UUID runId, int limit) {
        return db.sql("""
                SELECT run_id, attempt_id, rid, rule_id, control, alert_time, match_path, confidence
                FROM validation.v_api_alert_link WHERE run_id = :id
                ORDER BY alert_time, attempt_id LIMIT :lim""")
                .param("id", runId).param("lim", limit)
                .query((rs, i) -> new AlertLink(rs.getString("run_id"), lng(rs, "attempt_id"),
                        rs.getString("rid"), rs.getString("rule_id"), rs.getString("control"),
                        odt(rs, "alert_time"), rs.getString("match_path"), dbl(rs, "confidence"))).list();
    }

    // ── compare ────────────────────────────────────────────────────────────────
    /** before·after 가 공유하는 definition_version(철회 제외). 교집합이 비면 컨트롤러가 409. */
    public List<String> sharedDefinitionVersions(UUID before, UUID after) {
        return db.sql("""
                SELECT a.dv FROM
                  (SELECT DISTINCT definition_version dv FROM validation.metric_snapshot WHERE run_id = :before) a
                JOIN
                  (SELECT DISTINCT definition_version dv FROM validation.metric_snapshot WHERE run_id = :after) b
                  ON a.dv = b.dv
                ORDER BY 1""").param("before", before).param("after", after).query(String.class).list();
    }

    /**
     * 같은 definition_version 행끼리 직접 join + newcombe_diff_ci(ADR-S4-02 D4·ADR-S5-01). 재계산 없음.
     * 함수 규약: (x1,n1)=after, (x2,n2)=before, diff = p_after − p_before. → a=after, b=before 로 바인딩.
     * CompareRow 의 x1/n1 = after, x2/n2 = before.
     */
    public List<CompareRow> compare(UUID before, UUID after) {
        return db.sql("""
                SELECT a.metric_id, a.scope_kind, a.scope_key, a.definition_version,
                       a.numerator x1, a.denominator n1, b.numerator x2, b.denominator n2,
                       d.diff, d.lo, d.hi
                FROM validation.metric_snapshot a
                JOIN validation.metric_snapshot b
                  ON a.metric_id = b.metric_id AND a.scope_kind = b.scope_kind
                 AND a.definition_version = b.definition_version
                 AND coalesce(a.scope_key,'') = coalesce(b.scope_key,'')
                LEFT JOIN LATERAL validation.newcombe_diff_ci(a.numerator, a.denominator, b.numerator, b.denominator) d ON true
                WHERE a.run_id = :after AND b.run_id = :before
                  AND NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = a.run_id AND w.definition_version = a.definition_version)
                  AND NOT EXISTS (SELECT 1 FROM validation.metric_snapshot_withdrawal w
                                  WHERE w.run_id = b.run_id AND w.definition_version = b.definition_version)
                ORDER BY a.definition_version, a.metric_id, a.scope_kind, a.scope_key""")
                .param("before", before).param("after", after)
                .query((rs, i) -> new CompareRow(rs.getString("metric_id"), rs.getString("scope_kind"),
                        rs.getString("scope_key"), rs.getString("definition_version"),
                        lng(rs, "x1"), lng(rs, "n1"), lng(rs, "x2"), lng(rs, "n2"),
                        dbl(rs, "diff"), dbl(rs, "lo"), dbl(rs, "hi"))).list();
    }

    // ── helpers (null 안전) ─────────────────────────────────────────────────────
    private static boolean isZeroN(ResultSet rs, String col) throws SQLException {
        long v = rs.getLong(col);
        return rs.wasNull() || v == 0;
    }

    private static Long lng(ResultSet rs, String col) throws SQLException {
        long v = rs.getLong(col);
        return rs.wasNull() ? null : v;
    }

    private static Double dbl(ResultSet rs, String col) throws SQLException {
        double v = rs.getDouble(col);
        return rs.wasNull() ? null : v;
    }

    private static OffsetDateTime odt(ResultSet rs, String col) throws SQLException {
        return rs.getObject(col, OffsetDateTime.class);
    }
}
