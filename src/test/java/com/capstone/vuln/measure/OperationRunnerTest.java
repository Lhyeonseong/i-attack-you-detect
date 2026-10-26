package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 측정 도구 단위테스트 — Caldera 호출을 가짜 구현으로 대체해 생성 바디 구성·state 기반 종료·
 * 거짓완료 회귀·타임아웃·실패 전파를 검증한다(실제 HTTP/대기 없음, 가짜 시계로 결정적 실행).
 *
 * <p>완료 판정은 operation state 단일 진실원: {finished, cleanup, out_of_time} 만 종료,
 * running·paused 는 계속 폴링. chain link finish 추론은 제거됨(거짓 완료 원인).
 */
class OperationRunnerTest {

    private static final String ADVERSARY = "adv-attack-validation-web-001";
    private static final String PLANNER = "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a";
    private static final String SOURCE = "324b1d7b-c276-48a8-bd37-80009f2c3df0";

    /** 가짜 시계: sleeper 가 전진시킨다 → 실제 대기 없이 타임아웃 재현. */
    private static final class FakeTime implements TimeSource {
        private long ms;

        @Override
        public long millis() {
            return ms;
        }
    }

    /** create 는 고정 opId, poll 은 스크립트 순서대로 state 반환(소진 후 마지막 값 반복). */
    private static final class ScriptedApi implements CalderaOperations {
        private final String opId;
        private final Deque<String> pollStates;
        private String lastState;
        private OperationCreateRequest captured;
        private RuntimeException createError;
        private int pollCount;

        ScriptedApi(String opId, List<String> pollStates) {
            this.opId = opId;
            this.pollStates = new ArrayDeque<>(pollStates);
            this.lastState = pollStates.isEmpty() ? "running" : pollStates.get(pollStates.size() - 1);
        }

        @Override
        public String create(OperationCreateRequest request) {
            this.captured = request;
            if (createError != null) {
                throw createError;
            }
            return opId;
        }

        @Override
        public String poll(String id) {
            pollCount++;
            if (pollStates.isEmpty()) {
                return lastState;
            }
            lastState = pollStates.poll();
            return lastState;
        }
    }

    private static OperationRunner runner(CalderaOperations api, FakeTime time,
                                          long timeoutSeconds, long intervalSeconds) {
        Sleeper advancingSleeper = duration -> time.ms += duration.toMillis();
        return new OperationRunner(api, ADVERSARY, PLANNER, SOURCE, "red",
                Duration.ofSeconds(timeoutSeconds), Duration.ofSeconds(intervalSeconds),
                time, advancingSleeper);
    }

    @Test
    void create_body_is_composed_from_configured_ids_and_red_group() {
        ScriptedApi api = new ScriptedApi("op-1", List.of("finished"));

        String name = "S4-measure #1 2026-10-16T00:00:00Z";
        runner(api, new FakeTime(), 300, 3).runOnce(name);

        assertEquals(name, api.captured.name());
        assertEquals(ADVERSARY, api.captured.adversaryId());
        assertEquals(PLANNER, api.captured.plannerId());
        assertEquals(SOURCE, api.captured.sourceId());
        assertEquals("red", api.captured.group());
    }

    @Test
    void poll_terminates_when_state_finished_after_running() {
        // running → running → finished : finished 폴에서만 종료
        ScriptedApi api = new ScriptedApi("op-2", List.of("running", "running", "finished"));

        FakeTime time = new FakeTime();
        RunResult result = runner(api, time, 300, 5).runOnce("n");

        assertEquals("op-2", result.opId());
        assertEquals("finished", result.state());
        assertEquals(3, api.pollCount, "finished 가 나온 3번째 폴에서 종료해야 함");
        assertTrue(result.durationMs() >= 10000, "running 2회만큼(2×5s) 폴링 간격 경과");
    }

    @Test
    void poll_terminates_on_cleanup_state() {
        ScriptedApi api = new ScriptedApi("op-3", List.of("running", "cleanup"));
        RunResult result = runner(api, new FakeTime(), 300, 3).runOnce("n");
        assertEquals("cleanup", result.state());
        assertEquals("op-3", result.opId());
    }

    @Test
    void poll_terminates_on_out_of_time_state() {
        ScriptedApi api = new ScriptedApi("op-4", List.of("out_of_time"));
        RunResult result = runner(api, new FakeTime(), 300, 3).runOnce("n");
        assertEquals("out_of_time", result.state());
    }

    /**
     * ★거짓 완료 회귀: state=running 인 동안에는(그 시점 chain 의 현재 link 가 전부 finish 여도)
     * 종료하지 않고 계속 폴링해야 한다. 이번 스모크의 "BF 빠진 채 running 조기반환" 재발 방지.
     * state 가 끝내 running 에만 머물면 타임아웃으로만 끝나야 하며, 절대 finished 로 끝나지 않는다.
     */
    @Test
    void running_never_completes_even_if_links_look_finished() {
        ScriptedApi api = new ScriptedApi("op-5", List.of("running")); // 계속 running 반복
        FakeTime time = new FakeTime();

        RunResult result = runner(api, time, 30, 3).runOnce("n");

        assertEquals("timeout", result.state(), "running 은 종결 상태가 아니므로 완료로 끝나면 안 됨");
        assertEquals("op-5", result.opId());
        assertTrue(api.pollCount > 1, "running 동안 반복 폴링해야 함");
        assertTrue(result.durationMs() >= 30000, "타임아웃까지 경과");
    }

    @Test
    void timeout_returns_timeout_result_not_exception() {
        ScriptedApi api = new ScriptedApi("op-6", List.of("running"));
        FakeTime time = new FakeTime();

        RunResult result = runner(api, time, 10, 3).runOnce("n");

        assertEquals("op-6", result.opId());
        assertEquals("timeout", result.state());
        assertTrue(result.durationMs() >= 10000, "타임아웃(10s) 이상 경과 후 반환");
    }

    @Test
    void create_failure_propagates_as_exception() {
        ScriptedApi api = new ScriptedApi("op-7", List.of("finished"));
        api.createError = new IllegalStateException("Caldera operation 생성 실패: HTTP 400");

        assertThrows(IllegalStateException.class,
                () -> runner(api, new FakeTime(), 300, 3).runOnce("n"));
        assertEquals(0, api.pollCount, "생성 실패 시 poll 이 호출되면 안 됨");
    }
}
