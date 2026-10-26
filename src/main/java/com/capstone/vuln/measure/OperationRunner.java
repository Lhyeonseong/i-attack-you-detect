package com.capstone.vuln.measure;

import java.time.Duration;
import java.util.Set;

/**
 * S3-5b 측정 도구: Caldera operation 을 1회(runOnce) 생성·시작하고 완료까지 폴링한다.
 *
 * <p>측정 도구 ≠ 측정 대상 — 생산 앱(Controller/Validator/AttackLogger)과 분리된 패키지에 둔다.
 * 20회 반복·관찰 대기·Correlation/Verdict·DB 저장은 다음 슬라이스(S3-5b-2/3)의 책임이며 여기서 하지 않는다.
 *
 * <p>종료조건은 Caldera operation state 단일 진실원으로만 판정한다:
 * state ∈ {finished, cleanup, out_of_time} 이면 완료, running·paused 는 미완료로 계속 폴링.
 * (chain 의 link finish 추론은 쓰지 않는다 — atomic planner 가 link 를 점진 큐잉하므로 ability 사이
 * 빈 순간에 "현재 link 전부 finish"가 거짓 완료로 남는다.)
 * poll-timeout 초과 시 예외가 아니라 state="timeout" 결과로 반환한다.
 */
public class OperationRunner {

    /** Caldera 종결 state(완료로 간주). running·paused 는 제외. */
    private static final Set<String> TERMINAL_STATES = Set.of("finished", "cleanup", "out_of_time");

    private final CalderaOperations api;
    private final String adversaryId;
    private final String plannerId;
    private final String sourceId;
    private final String group;
    private final Duration pollTimeout;
    private final Duration pollInterval;
    private final TimeSource time;
    private final Sleeper sleeper;

    public OperationRunner(CalderaOperations api,
                           String adversaryId,
                           String plannerId,
                           String sourceId,
                           String group,
                           Duration pollTimeout,
                           Duration pollInterval,
                           TimeSource time,
                           Sleeper sleeper) {
        this.api = api;
        this.adversaryId = adversaryId;
        this.plannerId = plannerId;
        this.sourceId = sourceId;
        this.group = group;
        this.pollTimeout = pollTimeout;
        this.pollInterval = pollInterval;
        this.time = time;
        this.sleeper = sleeper;
    }

    /**
     * operation 1개를 생성·시작하고 완료(또는 타임아웃)까지 폴링한다.
     *
     * @param name operation 이름(가독성용 구분자). 귀속은 반환되는 opId 로 한다.
     * @return opId·최종 state·소요시간(ms)
     */
    public RunResult runOnce(String name) {
        long startMs = time.millis();
        String opId = api.create(new OperationCreateRequest(name, adversaryId, plannerId, sourceId, group));
        long deadlineMs = startMs + pollTimeout.toMillis();

        while (true) {
            String state = api.poll(opId);
            if (TERMINAL_STATES.contains(state)) {
                return new RunResult(opId, state, time.millis() - startMs);
            }
            if (time.millis() >= deadlineMs) {
                return new RunResult(opId, "timeout", time.millis() - startMs);
            }
            try {
                sleeper.sleep(pollInterval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("operation 폴링이 중단됨 (opId=" + opId + ")", e);
            }
        }
    }
}
