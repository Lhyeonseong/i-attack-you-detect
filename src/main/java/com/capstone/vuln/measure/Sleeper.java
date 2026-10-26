package com.capstone.vuln.measure;

import java.time.Duration;

/** 폴링 간격 대기(테스트에서 무대기/가짜 시계 전진으로 대체). */
@FunctionalInterface
public interface Sleeper {
    void sleep(Duration duration) throws InterruptedException;
}
