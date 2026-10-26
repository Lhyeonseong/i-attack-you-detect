package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.TestRuns;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * S4-2 V4 지표 뷰 테스트 픽스처 — OPEN run 에 verdict 를 쌓고 마지막에 VALID/INVALID/OPEN 으로 닫는다.
 * VALID = expected 를 실제 ATTACK·CONTROL 수로 맞춘 뒤 CLOSED (R10), INVALID = expected_attempts 를 1 어긋나게.
 *
 * <p>판정 값은 verdict 에 맞춰 일관되게 채운다: gt(S*→SUCCEEDED, F*·BLOCKED→FAILED, UNCERTAIN→UNKNOWN),
 * detection_status, 공격자 판정 기본 = gt 와 일치(UNCERTAIN 은 attacker 없음·match NULL).
 * 링크(M05): 멤버 correlation 1개당 source 1개, source 의 MatchPath·confidence 로 detection_link 1행
 * (NONE = TIME_ONLY 0.3). source 가 null 인 멤버는 링크 없는 correlation. 이 링크의 control 은 APP_RULE.
 * S4-4(M07a·M13): ctl(통제, rule_id[, technique]) 는 첫 멤버 correlation 에 통제 링크를 단다(멤버가 없으면 RID 멤버 1개 생성) —
 * APP_RULE = RID 1.0, NIDS = UA_FALLBACK 0.7. telemetry(앱로그, NIDS) 는 telemetry_observation 2행.
 * nidsCollected() = run 에 nids_window_stat 1행(R15 수집 여부).
 */
final class MetricFixture {

    /** V6 부터 지표 뷰 definition_version (ADR-S4-01 v1.7 R14 e — 식은 v1.4 와 같다) */
    static final String DEF_VERSION = "ADR-S4-01 v1.7";

    enum Close { VALID, INVALID, OPEN }

    /** 시도 1건 명세 (fluent) */
    static final class Attempt {
        String role = "ATTACK";
        final String scenario;
        final String technique;
        final String verdict;
        String initialVerdict;
        Long mttdMs;
        boolean late;
        String attackerVerdict;
        Boolean attackerMatch;
        boolean overestimate;
        List<String> memberSources = List.of();
        final List<String[]> controlLinks = new ArrayList<>();
        Integer appLogEvents;
        Integer nidsEvents;

        private Attempt(String scenario, String technique, String verdict) {
            this.scenario = scenario;
            this.technique = technique;
            this.verdict = verdict;
            this.initialVerdict = verdict;
            String gt = gtOf(verdict);
            if (!"UNKNOWN".equals(gt)) {
                this.attackerVerdict = gt;
                this.attackerMatch = true;
            }
            if (verdict.endsWith("_DETECTED")) {
                this.mttdMs = 1000L;
            }
        }

        Attempt initial(String v) { this.initialVerdict = v; return this; }
        Attempt mttd(long ms) { this.mttdMs = ms; return this; }
        Attempt late() { this.late = true; return this; }
        Attempt control() { this.role = "CONTROL"; return this; }
        Attempt links(String... sources) { this.memberSources = Arrays.asList(sources); return this; }

        /** 통제 링크 (technique = 시도 technique) */
        Attempt ctl(String control, String ruleId) { return ctl(control, ruleId, technique); }

        Attempt ctl(String control, String ruleId, String linkTechnique) {
            controlLinks.add(new String[] {control, ruleId, linkTechnique});
            return this;
        }

        Attempt telemetry(int appLog, int nids) {
            this.appLogEvents = appLog;
            this.nidsEvents = nids;
            return this;
        }

        Attempt attacker(String attacker, Boolean match, boolean over) {
            this.attackerVerdict = attacker;
            this.attackerMatch = match;
            this.overestimate = over;
            return this;
        }
    }

    static Attempt a(String scenario, String technique, String verdict) {
        return new Attempt(scenario, technique, verdict);
    }

    private final JdbcTemplate jdbc;
    final UUID runId;
    private int attacks;
    private int controls;
    private int seq;

    MetricFixture(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        this.runId = TestRuns.openTestRun(jdbc);
    }

    /** run.kind = BENIGN (M14 전용 run — D7 로 공격 지표 뷰에서 빠져야 한다) */
    MetricFixture benign() {
        jdbc.update("UPDATE validation.measurement_run SET kind = 'BENIGN' WHERE run_id = ?", runId);
        return this;
    }

    MetricFixture add(Attempt t) {
        int unit = seq++;
        List<String> members = t.memberSources.isEmpty() && !t.controlLinks.isEmpty()
                ? List.of("RID") : t.memberSources;
        double best = members.stream().mapToDouble(MetricFixture::confidence).max().orElse(0.0);
        String unitType = members.size() > 1 ? "SPRAY_CAMPAIGN"
                : "T1110".equals(t.technique) ? "BF_SEQUENCE" : "SINGLE";
        String uncertainReason = !"UNCERTAIN".equals(t.verdict) ? null
                : members.isEmpty() ? "NO_EVIDENCE" : "LOW_CONFIDENCE";
        Long verdictId = jdbc.queryForObject("""
                INSERT INTO validation.verdict_result (unit_key, unit_type, scenario, technique_id, verdict,
                    initial_verdict, uncertain_reason, detection_status, gt_outcome, attacker_verdict, attacker_match,
                    overestimate, best_confidence, mttd_ms, late_detection, spray_account_count, engine_version,
                    run_id, attempt_role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'test', ?, ?)
                RETURNING id""", Long.class,
                "unit:" + runId + ":" + unit, unitType, t.scenario, t.technique, t.verdict,
                t.initialVerdict, uncertainReason, detectionOf(t.verdict), gtOf(t.verdict), t.attackerVerdict,
                t.attackerMatch, t.overestimate, best, t.mttdMs, t.late, runId, t.role);

        for (int m = 0; m < members.size(); m++) {
            String source = members.get(m);
            Timestamp at = Timestamp.from(Instant.parse("2026-10-19T00:00:00Z"));
            Long correlationId = jdbc.queryForObject("""
                    INSERT INTO validation.correlation (correlation_key, op_id_resolved, scenario, technique_id,
                        attack_time, last_attack_time, observed_until, best_confidence, correlation_source,
                        bf_failure_count, bf_sequence, spray, spray_account_count)
                    VALUES (?, false, ?, ?, ?, ?, ?, ?, ?, 0, false, false, 0)
                    RETURNING id""", Long.class,
                    runId + ":" + unit + ":" + m, t.scenario == null ? "UNKNOWN" : t.scenario, t.technique,
                    at, at, at, confidence(source), source == null ? "NONE" : source);
            if (source != null && t.memberSources.contains(source)) {
                jdbc.update("""
                        INSERT INTO validation.detection_link (correlation_id, rule_id, technique, alert_time,
                            match_path, confidence, late, control)
                        VALUES (?, 'test', ?, ?, ?, ?, false, 'APP_RULE')""",
                        correlationId, t.technique, at, "NONE".equals(source) ? "TIME_ONLY" : source,
                        confidence(source));
            }
            if (m == 0) {
                for (String[] c : t.controlLinks) {
                    boolean nids = "NIDS".equals(c[0]);
                    jdbc.update("""
                            INSERT INTO validation.detection_link (correlation_id, rule_id, technique, alert_time,
                                match_path, confidence, late, control)
                            VALUES (?, ?, ?, ?, ?, ?, false, ?)""",
                            correlationId, c[1], c[2], at, nids ? "UA_FALLBACK" : "RID", nids ? 0.7 : 1.0, c[0]);
                }
            }
            jdbc.update("INSERT INTO validation.verdict_member (verdict_id, correlation_id) VALUES (?, ?)",
                    verdictId, correlationId);
        }

        if (t.appLogEvents != null) {
            jdbc.update("""
                    INSERT INTO validation.telemetry_observation (run_id, verdict_id, sensor, event_count)
                    VALUES (?, ?, 'APP_LOG', ?), (?, ?, 'NIDS', ?)""",
                    runId, verdictId, t.appLogEvents, runId, verdictId, t.nidsEvents);
        }

        if ("CONTROL".equals(t.role)) {
            controls++;
        } else {
            attacks++;
        }
        return this;
    }

    /** R15: 이 run 은 NIDS·텔레메트리를 수집했다 (nids_window_stat 1행 — 수치는 의미 없음) */
    MetricFixture nidsCollected() {
        jdbc.update("""
                INSERT INTO validation.nids_window_stat (run_id, op_id, window_start, window_end, nids_alerts,
                    orphan_alerts, analytic_alerts, analytic_linked, telemetry_alerts, marker_alerts, undecided_alerts,
                    unclassified_alerts, http_events, http_attributed)
                VALUES (?, 'fixture-op', now(), now(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)""", runId);
        return this;
    }

    MetricFixture add(int times, Attempt t) {
        for (int i = 0; i < times; i++) {
            add(t);
        }
        return this;
    }

    UUID close(Close close) {
        int expectedAttempts = close == Close.INVALID ? attacks + 1 : attacks;
        jdbc.update("UPDATE validation.measurement_run SET expected_attempts = ?, expected_controls = ? WHERE run_id = ?",
                expectedAttempts, controls, runId);
        if (close != Close.OPEN) {
            TestRuns.closeTestRun(jdbc, runId);
        }
        return runId;
    }

    /**
     * 픽스처 F1 (지시서 3 — x/n 기대값은 현성 확인 손계산).
     * 공격자 판정(T7 용, 지시서에 없는 값 — GateEvaluator 와 같은지만 본다):
     * SQLI FAILED_UNSEEN 1건 = 공격자 SUCCEEDED(불일치·과대평가), PT FAILED_UNSEEN 1건 = 공격자 없음(match NULL).
     */
    static MetricFixture f1(JdbcTemplate jdbc) {
        return new MetricFixture(jdbc)
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").mttd(1000))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").mttd(2000))
                .add(a("SQLI", "T1190", "SUCCEEDED_DETECTED").mttd(3000))
                .add(a("SQLI", "T1190", "SUCCEEDED_MISSED"))
                .add(a("SQLI", "T1190", "FAILED_UNSEEN").attacker("SUCCEEDED", false, true))
                .add(a("SQLI", "T1190", "UNCERTAIN"))
                .add(a("PATH_TRAVERSAL", "T1190", "SUCCEEDED_DETECTED").mttd(40000).late().initial("SUCCEEDED_MISSED"))
                .add(a("PATH_TRAVERSAL", "T1190", "FAILED_DETECTED"))
                .add(a("PATH_TRAVERSAL", "T1190", "FAILED_UNSEEN").attacker(null, null, false))
                .add(a("BRUTE_FORCE", "T1110", "SUCCEEDED_MISSED"))
                .add(a("UNKNOWN", "T1190", "SUCCEEDED_DETECTED").mttd(5000))
                .add(a("SSRF", "T1190", "FAILED_UNSEEN").control());
    }

    static double confidence(String source) {
        if (source == null) {
            return 0.0;
        }
        return switch (source) {
            case "RID" -> 1.0;
            case "HEADER" -> 0.9;
            case "UA_FALLBACK" -> 0.7;
            case "NONE" -> 0.3;
            default -> throw new IllegalArgumentException(source);
        };
    }

    private static String gtOf(String verdict) {
        if ("UNCERTAIN".equals(verdict)) {
            return "UNKNOWN";
        }
        return verdict.startsWith("SUCCEEDED") ? "SUCCEEDED" : "FAILED";
    }

    private static String detectionOf(String verdict) {
        return switch (verdict) {
            case "SUCCEEDED_DETECTED", "FAILED_DETECTED" -> "DETECTED";
            case "SUCCEEDED_BLOCKED", "BLOCKED" -> "BLOCKED";
            default -> "NOT_DETECTED";
        };
    }

    // ---- 뷰 조회 ----

    static Map<String, Object> rate(JdbcTemplate jdbc, UUID run, String metric, String kind, String unit) {
        return jdbc.queryForMap("""
                SELECT * FROM validation.v_metric_rates
                WHERE run_id = ? AND metric_id = ? AND split_kind = ? AND split_unit = ?""", run, metric, kind, unit);
    }

    static List<Map<String, Object>> rates(JdbcTemplate jdbc, UUID run, String metric) {
        return jdbc.queryForList("SELECT * FROM validation.v_metric_rates WHERE run_id = ? AND metric_id = ?",
                run, metric);
    }

    static long l(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).longValue();
    }

    static double d(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).doubleValue();
    }

    /** "x/n" 표기 */
    static String xn(Map<String, Object> row) {
        return l(row, "x") + "/" + l(row, "n");
    }

    static List<String> units(List<Map<String, Object>> rows) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> r : rows) {
            out.add(r.get("split_kind") + ":" + r.get("split_unit"));
        }
        out.sort(null);
        return out;
    }
}
