package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.util.List;
import java.util.UUID;

/**
 * validation.verdict_result 를 게이트 표본으로 읽는다(기존 스키마 조회만, VerdictRepository 미수정).
 * truncate 는 본측정 전 초기화용(verdict_result/member/history).
 * S4-1: 표본은 run 하나·ATTACK 만 (R4 run 간 합산 금지, R6 대조군은 공격 지표 분모 제외 — M09 포함).
 * S4-1a: CLOSED run(완료된 측정·백필 baseline)이 하나라도 있으면 truncate 를 거부한다 — 아무것도 지우지 않는다.
 * S4-3: metric_snapshot 에 행이 있어도 같은 방식으로 거부한다.
 */
public class GateVerdictReader implements VerdictSampleSource {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public GateVerdictReader(DataSource validationDataSource) {
        this.jdbc = new JdbcTemplate(validationDataSource);
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(validationDataSource));
    }

    @Override
    public List<VerdictSample> loadSamples(UUID runId) {
        return jdbc.query("""
                SELECT scenario, verdict, attacker_match, overestimate FROM validation.verdict_result
                WHERE run_id = ? AND attempt_role = 'ATTACK'""",
                (rs, n) -> new VerdictSample(
                        rs.getString("scenario"),
                        "UNCERTAIN".equals(rs.getString("verdict")),
                        (Boolean) rs.getObject("attacker_match"),
                        rs.getBoolean("overestimate")), runId);
    }

    @Override
    public void truncateAll() {
        tx.executeWithoutResult(status -> {
            // 확인 ~ TRUNCATE 사이에 run 이 CLOSED 로 바뀌지 않도록 (close 의 UPDATE 를 막는 락)
            jdbc.execute("LOCK TABLE validation.measurement_run IN SHARE MODE");
            Integer closed = jdbc.queryForObject(
                    "SELECT count(*) FROM validation.measurement_run WHERE status = 'CLOSED'", Integer.class);
            if (closed != null && closed > 0) {
                throw new IllegalStateException("CLOSED run " + closed + "개 존재 — truncate 거부(아무것도 지우지 않음). "
                        + "run 단위 집계라 truncate 가 필요 없다");
            }
            // S4-3: 스냅샷은 불변 기록(ADR-S4-01 R13) — 원천 verdict 를 지우면 스냅샷과 대조할 수 없다
            Integer snapshots = jdbc.queryForObject("SELECT count(*) FROM validation.metric_snapshot", Integer.class);
            if (snapshots != null && snapshots > 0) {
                throw new IllegalStateException("metric_snapshot " + snapshots + "행 존재 — truncate 거부(아무것도 지우지 않음). "
                        + "스냅샷은 불변 기록이다(ADR-S4-01 R13)");
            }
            jdbc.execute("TRUNCATE validation.verdict_result, validation.verdict_member, "
                    + "validation.verdict_history RESTART IDENTITY CASCADE");
        });
    }
}
