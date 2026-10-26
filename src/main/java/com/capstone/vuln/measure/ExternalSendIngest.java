package com.capstone.vuln.measure;

import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.IntFunction;

/**
 * 외부 전송 BENIGN run (ADR-S4-01 v2.0 R17 f) — 전송은 코드가 하지 않고 사람이 터미널에서 실행한 뒤,
 * 전송 기록 CSV(seq,sent_at_ms,responded_at_ms,status)를 입력으로 받아 대조·적재·연결·판정한다.
 * login run(S4-5-BENIGN-LOGIN) 전용이 아니라 전송 기록만 받는 일반 경로이며, 통제 적용은 benign_endpoint 설정(scenario)만 따른다.
 *
 * <p>두 모드:
 * <ul>
 *   <li>open: benign_endpoint 에 있는 endpoint 로 OPEN BENIGN run 생성(expected = 계획 요청 수). 전송은 사람이 한다</li>
 *   <li>ingest: 결과 CSV → §I 검사(형식·seq 연속·단일 후보) → 앱 로그 대조 → benign_request 적재 → 연결 → close.
 *       §I 위반이면 적재 전 실패하고 run 은 OPEN 으로 두며 사유를 notes 에 남긴다(사람이 닫음, run dffb77a7 선례와 같은 방식)</li>
 * </ul>
 * 적재·연결은 {@link BenignIngest}(BenignWebRun 과 공통)를 그대로 쓴다. 비밀번호는 계획·코드·로그·DB 어디에도 두지 않는다(CWE-798).
 */
public class ExternalSendIngest {

    /** §I 단일 후보: 다음 전송 − 이전 응답 > 2×TOLERANCE (앱 로그·NIDS 대조 창이 겹치지 않도록). 새 상수 금지 — BenignLogReader 재사용 */
    public static final Duration SINGLE_CANDIDATE_GAP = BenignLogReader.TOLERANCE.multipliedBy(2);
    public static final String RESULT_HEADER = "seq,sent_at_ms,responded_at_ms,status";

    private record Row(int seq, long sentMs, long respondedMs, int status) {
    }

    private final MeasurementRunRepository runs;
    private final BenignIngest ingest;
    private final JdbcTemplate jdbc;

    public ExternalSendIngest(DataSource validationDataSource, MeasurementRunRepository runs, BenignIngest ingest) {
        this.runs = runs;
        this.ingest = ingest;
        this.jdbc = new JdbcTemplate(validationDataSource);
    }

    /**
     * OPEN BENIGN run 생성. endpoint 는 benign_endpoint 에 있어야 하고, expected_attempts = 계획 요청 수.
     * @param openRun 기대 요청 수 → 새 BENIGN run (label·git·rules_digest 는 호출 쪽이 정한다)
     */
    public UUID open(IntFunction<MeasurementRun> openRun, LoginPlan plan, String endpoint) {
        Integer known = jdbc.queryForObject(
                "SELECT count(*) FROM validation.benign_endpoint WHERE endpoint = ?", Integer.class, endpoint);
        if (known == null || known == 0) {
            throw new IllegalStateException("benign_endpoint 에 없는 endpoint: " + endpoint + " (V9 이후여야 한다)");
        }
        MeasurementRun run = openRun.apply(plan.size());
        if (run.kind() != MeasurementRun.Kind.BENIGN) {
            throw new IllegalStateException("BENIGN run 이 아니다: " + run.kind());
        }
        runs.open(run);
        UUID runId = run.runId();
        System.out.println("BENIGN>> external open label=" + run.label() + " run_id=" + runId + " endpoint=" + endpoint
                + " expected=" + plan.size());
        return runId;
    }

    /** 결과 CSV ingest. §I 위반이면 적재 전 실패(run OPEN 유지·사유 notes 기록). 정상이면 close 까지. */
    public void ingest(UUID runId, LoginPlan plan, Path resultCsv) {
        List<Row> rows = parse(resultCsv);
        String violation = checkIntegrity(rows, plan);
        if (violation != null) {
            runs.recordNotes(runId, "aborted: external send ingest §I — " + violation);
            throw new IllegalStateException("§I 무결성 위반 — 적재하지 않음 (run " + runId + " OPEN 유지): " + violation);
        }
        List<BenignSent> sent = new ArrayList<>(rows.size());
        for (Row r : rows) {
            LoginPlan.Entry e = plan.bySeq(r.seq());
            String appArgs = LoginPlan.PARAM + "=" + e.username();
            sent.add(new BenignSent(r.seq(), LoginPlan.ENDPOINT, LoginPlan.ENDPOINT, appArgs,
                    Instant.ofEpochMilli(r.sentMs()), Instant.ofEpochMilli(r.respondedMs()), r.status()));
        }
        System.out.println("BENIGN>> external ingest run_id=" + runId + " rows=" + sent.size()
                + " endpoint=" + LoginPlan.ENDPOINT);
        ingest.apply(runId, sent);
    }

    private static List<Row> parse(Path resultCsv) {
        List<String> lines;
        try {
            lines = Files.readAllLines(resultCsv, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<String> content = new ArrayList<>();
        for (String raw : lines) {
            String line = raw.strip();
            if (!line.isEmpty() && !line.startsWith("#")) {
                content.add(line);
            }
        }
        if (content.isEmpty() || !RESULT_HEADER.equals(content.get(0))) {
            throw new IllegalStateException("결과 CSV 헤더가 '" + RESULT_HEADER + "' 이 아니다: " + resultCsv);
        }
        List<Row> rows = new ArrayList<>();
        for (int i = 1; i < content.size(); i++) {
            String[] f = content.get(i).split(",", -1);
            if (f.length != 4) {
                throw new IllegalStateException("결과 CSV 행 열 수가 4가 아니다 (행 " + (i + 1) + "): " + content.get(i));
            }
            try {
                rows.add(new Row(Integer.parseInt(f[0].strip()), Long.parseLong(f[1].strip()),
                        Long.parseLong(f[2].strip()), Integer.parseInt(f[3].strip())));
            } catch (NumberFormatException e) {
                throw new IllegalStateException("결과 CSV 숫자 파싱 실패 (행 " + (i + 1) + "): " + content.get(i), e);
            }
        }
        if (rows.isEmpty()) {
            throw new IllegalStateException("결과 CSV 에 요청 행이 없다: " + resultCsv);
        }
        return rows;
    }

    /** §I 검사 — 위반 사유(한 줄) 반환, 통과면 null. 적재 전에 부른다. */
    private static String checkIntegrity(List<Row> rows, LoginPlan plan) {
        if (rows.size() != plan.size()) {
            return "결과 행 수 " + rows.size() + " ≠ 계획 요청 수 " + plan.size();
        }
        long gapMs = SINGLE_CANDIDATE_GAP.toMillis();
        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            if (r.seq() != i + 1) {
                return "seq 가 1부터 빈틈없이 증가하지 않는다: " + r.seq() + " (기대 " + (i + 1) + ")";
            }
            if (r.sentMs() > r.respondedMs()) {
                return "sent_at_ms > responded_at_ms (seq " + r.seq() + ")";
            }
            if (i > 0) {
                long prevResponded = rows.get(i - 1).respondedMs();
                if (r.sentMs() - prevResponded <= gapMs) {
                    return "단일 후보 조건 위반 (seq " + r.seq() + "): 다음 전송 − 이전 응답 = "
                            + (r.sentMs() - prevResponded) + " ms ≤ 2×TOLERANCE(" + gapMs + " ms)";
                }
            }
        }
        return null;
    }
}
