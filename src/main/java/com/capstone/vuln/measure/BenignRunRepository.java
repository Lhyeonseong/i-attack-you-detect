package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * BENIGN run 적재 (validation.benign_request·benign_result·benign_unlinked_alert, V7) — 한 트랜잭션.
 * 값 원문(검색어·파일명·URL)은 저장하지 않고 args_digest(sha256)만 둔다 — 원문은 manifest 에 있다.
 * DB 트리거가 OPEN BENIGN run 에만 INSERT 를 허용한다.
 */
public class BenignRunRepository {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public BenignRunRepository(DataSource validationDataSource) {
        this.jdbc = new JdbcTemplate(validationDataSource);
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(validationDataSource));
    }

    /** 요청·판정·미연결을 한 트랜잭션으로 */
    public void save(UUID runId, List<BenignSent> sent, Map<Integer, String> ridBySeq, BenignAlertLinker.Result linked) {
        tx.executeWithoutResult(status -> {
            insertRequests(runId, sent, ridBySeq);
            insertLinks(runId, linked);
        });
    }

    /**
     * 요청만 먼저 적재(전송·응답 시각·상태·대조 rid) — 앱 로그 대조 직후에 부른다. 뒤 단계(알림 읽기·연결)가 실패해도
     * 전송 기록과 R10 적재·대조 수가 남는다(S4-5 BenignRunIT 실패 — 2026-10-22 s4-5-benign 로그 (3-F))
     */
    public void saveRequests(UUID runId, List<BenignSent> sent, Map<Integer, String> ridBySeq) {
        tx.executeWithoutResult(status -> insertRequests(runId, sent, ridBySeq));
    }

    /** 판정·미연결 적재 (saveRequests 뒤) */
    public void saveLinks(UUID runId, BenignAlertLinker.Result linked) {
        tx.executeWithoutResult(status -> insertLinks(runId, linked));
    }

    private void insertRequests(UUID runId, List<BenignSent> sent, Map<Integer, String> ridBySeq) {
        jdbc.batchUpdate("""
                INSERT INTO validation.benign_request (run_id, seq, endpoint, args_digest, sent_at, responded_at, status,
                    matched_rid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", sent, 200, (ps, s) -> {
            ps.setObject(1, runId);
            ps.setInt(2, s.seq());
            ps.setString(3, s.endpoint());
            ps.setString(4, sha256(s.appArgs()));
            ps.setObject(5, ts(s.sentAt()));
            ps.setObject(6, ts(s.respondedAt()));
            ps.setInt(7, s.status());
            ps.setString(8, ridBySeq.get(s.seq()));
        });
    }

    private void insertLinks(UUID runId, BenignAlertLinker.Result linked) {
        jdbc.batchUpdate("""
                INSERT INTO validation.benign_result (run_id, seq, control, alerted, linked_rule_ids, alert_count,
                    recorded_rule_ids)
                VALUES (?, ?, ?, ?, ?, ?, ?)""", linked.results(), 200, (ps, r) -> {
            ps.setObject(1, runId);
            ps.setInt(2, r.seq());
            ps.setString(3, r.control());
            ps.setBoolean(4, r.alerted());
            ps.setArray(5, ps.getConnection().createArrayOf("text", r.linkedRuleIds().toArray()));
            ps.setInt(6, r.alertCount());
            ps.setArray(7, ps.getConnection().createArrayOf("text", r.recordedRuleIds().toArray()));
        });
        jdbc.batchUpdate("""
                INSERT INTO validation.benign_unlinked_alert (run_id, sensor, rule_id, alert_time, reason)
                VALUES (?, ?, ?, ?, ?)""", linked.unlinked(), 200, (ps, u) -> {
            ps.setObject(1, runId);
            ps.setString(2, u.sensor());
            ps.setString(3, u.ruleId());
            ps.setObject(4, ts(u.alertTime()));
            ps.setString(5, u.reason());
        });
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Object ts(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
