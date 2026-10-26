package com.capstone.vuln.measure;

/**
 * 측정 시점 저장소 상태 — commit = git rev-parse HEAD, dirty = git status --porcelain 출력 유무.
 * dirty 는 primitive: 새 run 은 "알 수 없음"을 가질 수 없다.
 */
public record GitState(String commit, boolean dirty) {

    public GitState {
        if (commit == null || commit.isBlank()) {
            throw new IllegalArgumentException("git commit 이 비어 있음");
        }
    }
}
