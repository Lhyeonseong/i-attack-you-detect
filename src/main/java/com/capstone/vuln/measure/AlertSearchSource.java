package com.capstone.vuln.measure;

import java.time.Instant;

/**
 * 인덱서 alert 검색 응답(JSON) 공급 — op 창 [from, toInclusive] 로 범위 제한한 _search 결과.
 * 테스트는 고정 샘플 JSON, 운영은 인덱서 HTTP 질의(주입).
 */
@FunctionalInterface
public interface AlertSearchSource {
    String search(Instant fromInclusive, Instant toInclusive);
}
