package com.capstone.vuln.measure;

/**
 * 게이트 집계용 표본 1건 (= verdict_result 1행). 값은 전부 저장된 verdict_result 에서 읽은 것 —
 * 게이트는 match/overestimate 를 새로 계산하지 않고 이 값만 임계와 비교한다.
 *
 * - uncertain: verdict == UNCERTAIN (matchRate 분모에서 제외, 비율 가드레일로 별도 집계)
 * - attackerMatch: gt=UNKNOWN/attacker 없음이면 null
 * - overestimate: attacker=SUCCEEDED & gt=FAILED
 */
public record VerdictSample(String scenario, boolean uncertain, Boolean attackerMatch, boolean overestimate) {
}
