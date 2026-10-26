package com.capstone.vuln.correlation;

import java.util.List;

/**
 * 연결된 탐지 링크들에서 최고 신뢰도와 대표 채널을 산출한다.
 * - bestConfidence: 링크 중 최고 confidence (링크 없으면 0)
 * - source: 1.0→RID, 0.9→HEADER, 0.7→UA_FALLBACK, 그 외(TIME_ONLY 만/링크 없음)→NONE
 */
public final class ConfidenceResolver {

    public record Resolution(double bestConfidence, MatchSource source) {
    }

    private ConfidenceResolver() {
    }

    public static Resolution resolve(List<DetectionLink> links) {
        double best = links.stream()
                .mapToDouble(DetectionLink::confidence)
                .max()
                .orElse(0.0);
        return new Resolution(best, sourceOf(best));
    }

    static MatchSource sourceOf(double confidence) {
        if (confidence >= Confidence.of(MatchPath.RID).value()) return MatchSource.RID;
        if (confidence >= Confidence.of(MatchPath.HEADER).value()) return MatchSource.HEADER;
        if (confidence >= Confidence.of(MatchPath.UA_FALLBACK).value()) return MatchSource.UA_FALLBACK;
        return MatchSource.NONE;
    }
}
