package com.capstone.vuln.correlation;

/**
 * 상관분석 신뢰도. MatchPath 별 고정 등급이며 THRESHOLD 이상만 Verdict 근거로 쓴다.
 */
public record Confidence(double value) {

    public static final double THRESHOLD = 0.7;

    public static Confidence of(MatchPath path) {
        return switch (path) {
            case RID -> new Confidence(1.0);
            case HEADER -> new Confidence(0.9);
            case UA_FALLBACK -> new Confidence(0.7);
            case TIME_ONLY -> new Confidence(0.3);
        };
    }

    public boolean usableForVerdict() {
        return value >= THRESHOLD;
    }
}
