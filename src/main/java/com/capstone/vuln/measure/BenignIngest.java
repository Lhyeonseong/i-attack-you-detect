package com.capstone.vuln.measure;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * 전송 뒤 공통 적재 파이프라인 (ADR-S4-01 R17 c·R18 a~c·g) — BenignWebRun(하네스 직접 전송)과
 * ExternalSendIngest(외부 전송 + 결과 CSV, R17 f)가 공유한다. 전송 방식과 무관하게 {@link BenignSent} 목록만 받는다.
 *
 * <p>순서(실패 시 남는 것은 BenignWebRun javadoc 과 같다):
 * <ol>
 *   <li>앱 로그 대조 직후 benign_request 선적재 — 이후 실패해도 전송 기록·R10 적재 수가 남는다</li>
 *   <li>알림 읽기 → 연결 → benign_result·benign_unlinked_alert 적재 → close</li>
 * </ol>
 * 출력 문자열은 기존 BenignWebRun 과 동일하게 유지한다(두 경로가 같은 로그를 낸다).
 */
public class BenignIngest {

    private final MeasurementRunRepository runs;
    private final BenignLogReader logReader;
    private final BenignAlertReader alertReader;
    private final BenignAlertLinker linker;
    private final BenignRunRepository repository;
    private final Duration observation;
    private final TimeSource time;

    public BenignIngest(MeasurementRunRepository runs, BenignLogReader logReader, BenignAlertReader alertReader,
                        BenignAlertLinker linker, BenignRunRepository repository, Duration observation, TimeSource time) {
        this.runs = runs;
        this.logReader = logReader;
        this.alertReader = alertReader;
        this.linker = linker;
        this.repository = repository;
        this.observation = observation;
        this.time = time;
    }

    /** 대조 → 선적재 → 알림 읽기 → 연결 → 적재 → close. run 은 OPEN BENIGN 이어야 한다(트리거가 막는다) */
    public void apply(java.util.UUID runId, List<BenignSent> sent) {
        BenignLogReader.Match match = logReader.match(sent);
        repository.saveRequests(runId, sent, match.ridBySeq());
        System.out.println("BENIGN>> app log matched=" + match.ridBySeq().size() + "/" + sent.size()
                + " unmatched_untagged_lines=" + match.unmatchedUntaggedLines() + " benign_request saved=" + sent.size());

        Instant from = sent.get(0).sentAt().minusSeconds(1);
        Instant to = sent.get(sent.size() - 1).respondedAt().plus(observation);
        List<BenignAppAlert> app = alertReader.readApp(from, to);
        List<BenignNidsAlert> nids = alertReader.readNids(from, to);
        BenignAlertLinker.Result linked = linker.link(sent, match.ridBySeq(), app, nids);
        repository.saveLinks(runId, linked);
        System.out.println("BENIGN>> alerts app=" + app.size() + " nids=" + nids.size() + " results="
                + linked.results().size() + " fp=" + linked.results().stream().filter(BenignResult::alerted).count()
                + " unlinked=" + linked.unlinked().size());

        runs.close(runId, Instant.ofEpochMilli(time.millis()));
    }
}
