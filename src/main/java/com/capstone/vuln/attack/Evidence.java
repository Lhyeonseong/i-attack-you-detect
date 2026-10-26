package com.capstone.vuln.attack;

import java.util.Objects;

/**
 * 판정 근거
 * - summary: 사람이 읽는 요약. 비밀번호, 응답 본문 등 민감값 원문은 넣지 않는다 (요약/패턴만)
 * - fingerprint: 같은 종류의 근거를 묶기 위한 비민감 식별자
 */
public record Evidence(EvidenceKind kind, String summary, String fingerprint) {

    public enum EvidenceKind {
        RESPONSE_PATTERN,
        STATE_CHANGE,
        DATA_EXPOSURE,
        FILE_DISCLOSED,
        CREDENTIAL_VALID,
        AUTH_GRANT,
        TIMING,
        DIFFERENTIAL,
        /** SSRF: 서버가 내부 전용 메타데이터/리소스에 실제 도달했음 (sentinel 또는 내부 대역 응답) */
        METADATA_REACHED
    }

    public Evidence {
        Objects.requireNonNull(kind, "kind");
    }
}
