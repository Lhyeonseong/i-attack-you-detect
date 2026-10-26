package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * validation.measurement_run 저장소 — open(OPEN 행 INSERT) / close(OPEN → CLOSED, ended_at).
 * 새 run 의 git_dirty NULL 은 거부한다(NULL 은 백필 SQL 로만 들어온다).
 */
public class MeasurementRunRepository {

    /** run 에 귀속된 verdict 의 역할별 건수 (R10 실제값) */
    public record RoleCounts(long attacks, long controls) {
    }

    private final JdbcTemplate jdbc;

    public MeasurementRunRepository(DataSource validationDataSource) {
        this.jdbc = new JdbcTemplate(validationDataSource);
    }

    public void open(MeasurementRun run) {
        if (run.gitDirty() == null) {
            throw new IllegalArgumentException("새 run 은 git_dirty 를 알아야 한다 (NULL 은 백필 전용)");
        }
        if (run.status() != MeasurementRun.Status.OPEN || run.endedAt() != null) {
            throw new IllegalArgumentException("open 은 OPEN·ended_at 없음 상태만");
        }
        jdbc.update("""
                INSERT INTO validation.measurement_run (run_id, label, kind, status, started_at, ended_at, git_commit,
                    git_dirty, rules_digest, expected_attempts, expected_controls, notes)
                VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?::jsonb, ?, ?, ?)""",
                run.runId(), run.label(), run.kind().name(), run.status().name(), ts(run.startedAt()),
                run.gitCommit(), run.gitDirty(), run.rulesDigestJson(), run.expectedAttempts(),
                run.expectedControls(), run.notes());
    }

    /**
     * OPEN run 의 notes 만 갱신(사유 기록) — ExternalSendIngest §I 위반 시 run 은 OPEN 으로 두고 사유만 남긴다(사람이 닫음).
     * run dffb77a7 선례처럼 r10_reason(BENIGN_LOAD_MISMATCH)은 닫을 때 뷰가 계산하고, 구체 원인은 notes 에 둔다.
     */
    public void recordNotes(UUID runId, String notes) {
        int updated = jdbc.update("UPDATE validation.measurement_run SET notes = ? WHERE run_id = ? AND status = 'OPEN'",
                notes, runId);
        if (updated != 1) {
            throw new IllegalStateException("OPEN 상태 run 이 아님: " + runId);
        }
    }

    public void close(UUID runId, Instant endedAt) {
        int updated = jdbc.update("""
                UPDATE validation.measurement_run SET status = 'CLOSED', ended_at = ?
                WHERE run_id = ? AND status = 'OPEN'""", ts(endedAt), runId);
        if (updated != 1) {
            throw new IllegalStateException("OPEN 상태 run 이 아님: " + runId);
        }
    }

    public Optional<MeasurementRun> find(UUID runId) {
        List<MeasurementRun> rows = jdbc.query("SELECT * FROM validation.measurement_run WHERE run_id = ?",
                (rs, n) -> {
                    OffsetDateTime ended = rs.getObject("ended_at", OffsetDateTime.class);
                    return new MeasurementRun(
                            rs.getObject("run_id", UUID.class),
                            rs.getString("label"),
                            MeasurementRun.Kind.valueOf(rs.getString("kind")),
                            MeasurementRun.Status.valueOf(rs.getString("status")),
                            rs.getObject("started_at", OffsetDateTime.class).toInstant(),
                            ended == null ? null : ended.toInstant(),
                            rs.getString("git_commit"),
                            rs.getObject("git_dirty", Boolean.class),
                            rs.getString("rules_digest"),
                            rs.getObject("expected_attempts", Integer.class),
                            rs.getObject("expected_controls", Integer.class),
                            rs.getString("notes"));
                }, runId);
        return rows.stream().findFirst();
    }

    public RoleCounts roleCounts(UUID runId) {
        Map<String, Object> row = jdbc.queryForMap("""
                SELECT count(*) FILTER (WHERE attempt_role = 'ATTACK') AS attacks,
                       count(*) FILTER (WHERE attempt_role = 'CONTROL') AS controls
                FROM validation.verdict_result WHERE run_id = ?""", runId);
        return new RoleCounts(((Number) row.get("attacks")).longValue(), ((Number) row.get("controls")).longValue());
    }

    /** R10 판정 — validation.v_run_integrity 1행 (단일 원천) */
    public Optional<SampleIntegrity.Result> integrity(UUID runId) {
        List<SampleIntegrity.Result> rows = jdbc.query("SELECT * FROM validation.v_run_integrity WHERE run_id = ?",
                (rs, n) -> SampleIntegrity.fromView(
                        rs.getString("r10_status"),
                        rs.getString("r10_reason"),
                        rs.getObject("expected_attempts", Integer.class),
                        rs.getObject("expected_controls", Integer.class),
                        rs.getLong("actual_attack"),
                        rs.getLong("actual_control")), runId);
        return rows.stream().findFirst();
    }

    private static OffsetDateTime ts(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
