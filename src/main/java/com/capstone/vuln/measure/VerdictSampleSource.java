package com.capstone.vuln.measure;

import java.util.List;
import java.util.UUID;

/** 게이트 표본 공급·초기화 seam — 운영은 validation.verdict_result 조회(주입), 테스트는 가짜. */
public interface VerdictSampleSource {

    /** run 하나의 verdict_result(ATTACK 만, R4·R6)를 게이트 표본으로 읽는다. */
    List<VerdictSample> loadSamples(UUID runId);

    /** 본측정 전 초기화 — verdict_result/member/history 비우기. CLOSED run 이 있으면 예외(아무것도 지우지 않음). */
    void truncateAll();
}
