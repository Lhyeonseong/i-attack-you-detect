package com.capstone.vuln.measure;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.IntFunction;
import java.util.stream.Collectors;

/**
 * BENIGN 웹 run 1회 (ADR-S4-01 v1.8 R17·R18) — BenignRunIT 가 실제 구성요소로 부르고, 테스트는 가짜로 부른다.
 *
 * <p>순서와 실패 시 남는 것:
 * <ol>
 *   <li>사전 시험: 인덱서 두 질의(앱 룰·NIDS)를 1초 창으로 한 번씩 — 실패하면 run 을 열지 않고 아무것도 보내지 않는다</li>
 *   <li>run open(kind BENIGN, expected = 코퍼스 요청 수) → 순차 전송 → 읽기 대기</li>
 *   <li>앱 로그 대조 직후 benign_request 선적재(전송·응답 시각, 상태, rid) — 이후 실패해도 전송 기록·R10 적재 수가 남는다</li>
 *   <li>알림 읽기 → 연결 → benign_result·benign_unlinked_alert 적재 → close</li>
 * </ol>
 * 2 이후 단계에서 실패하면 run 은 OPEN(INCOMPLETE)으로 남는다 — 닫을지는 사람이 정한다.
 */
public class BenignWebRun {

    private final MeasurementRunRepository runs;
    private final IntFunction<MeasurementRun> openRun;
    private final BenignCorpusRunner runner;
    private final BenignLogReader logReader;
    private final BenignAlertReader alertReader;
    private final BenignAlertLinker linker;
    private final BenignRunRepository repository;
    private final BenignCorpusRunner.Sleeper sleeper;
    private final Duration readWait;
    private final Duration observation;
    private final TimeSource time;

    /** @param openRun 기대 요청 수 → 새 BENIGN run (label·git·rules_digest 는 호출 쪽이 정한다) */
    public BenignWebRun(MeasurementRunRepository runs, IntFunction<MeasurementRun> openRun, BenignCorpusRunner runner,
                        BenignLogReader logReader, BenignAlertReader alertReader, BenignAlertLinker linker,
                        BenignRunRepository repository, BenignCorpusRunner.Sleeper sleeper, Duration readWait,
                        Duration observation, TimeSource time) {
        this.runs = runs;
        this.openRun = openRun;
        this.runner = runner;
        this.logReader = logReader;
        this.alertReader = alertReader;
        this.linker = linker;
        this.repository = repository;
        this.sleeper = sleeper;
        this.readWait = readWait;
        this.observation = observation;
        this.time = time;
    }

    public UUID execute(BenignCorpus corpus) throws InterruptedException {
        Instant now = Instant.ofEpochMilli(time.millis());
        alertReader.readApp(now.minusSeconds(1), now);
        alertReader.readNids(now.minusSeconds(1), now);
        System.out.println("BENIGN>> preflight indexer OK (app rule group + 86601)");

        MeasurementRun run = openRun.apply(corpus.items().size());
        if (run.kind() != MeasurementRun.Kind.BENIGN) {
            throw new IllegalStateException("BENIGN run 이 아니다: " + run.kind());
        }
        runs.open(run);
        UUID runId = run.runId();
        System.out.println("BENIGN>> run open label=" + run.label() + " run_id=" + runId + " corpus=" + corpus.name()
                + " items=" + corpus.items().size());

        List<BenignSent> sent = runner.run(corpus.items());
        Map<String, Long> byStatus = sent.stream().collect(Collectors.groupingBy(
                s -> s.endpoint() + " " + s.status(), TreeMap::new, Collectors.counting()));
        System.out.println("BENIGN>> sent first=" + sent.get(0).sentAt() + " last=" + sent.get(sent.size() - 1).respondedAt()
                + " status=" + byStatus);

        sleeper.sleep(readWait);
        new BenignIngest(runs, logReader, alertReader, linker, repository, observation, time).apply(runId, sent);
        return runId;
    }
}
