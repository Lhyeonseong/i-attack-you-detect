package com.capstone.vuln.measure;

/** 경과시간 측정용 시계(테스트에서 가짜 시계로 대체). */
@FunctionalInterface
public interface TimeSource {
    long millis();
}
