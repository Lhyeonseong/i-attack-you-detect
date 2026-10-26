package com.capstone.validationapi.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * API 응답 DTO 모음(ADR-S4-02 D4). snake_case 직렬화(application.yml jackson).
 * 비율 지표는 x·n 을 항상 함께, n=0 이면 p·lo·hi 는 null(ADR-S4-01 n=0 규칙).
 */
public final class ApiDtos {

    private ApiDtos() {
    }

    /** /meta */
    public record Meta(List<String> definitionVersions, String latestDefinitionVersion,
                       int runCount, NavigatorVersions navigator) {
    }

    public record NavigatorVersions(String attack, String navigator, String layer) {
    }

    /** /runs, /runs/{id} */
    public record Run(String runId, String label, String kind, String status,
                      OffsetDateTime startedAt, OffsetDateTime endedAt,
                      String gitCommit, Boolean gitDirty, String integrityStatus,
                      Integer expectedAttempts, Integer expectedControls,
                      List<String> definitionVersions, List<Provenance> provenance) {
    }

    /** run_provenance_note (D11). */
    public record Provenance(String item, String value, String sourceFile, Integer sourceLine) {
    }

    /** 비율 지표 공통(rates·coverage). */
    public record Rate(String metricId, String scopeKind, String scopeKey,
                       Long x, Long n, Double p, Double lo, Double hi,
                       String status, String definitionVersion) {
    }

    /** correlation(출처별 x). */
    public record Correlation(String scopeKind, String scopeKey, String source,
                              Long x, Long n, Double p, Double lo, Double hi,
                              String status, String definitionVersion) {
    }

    /** attacker 판정 정확도(과대추정·불확실 별도 열). */
    public record Attacker(String scopeKind, String scopeKey, Long x, Long n,
                           Double p, Double lo, Double hi, Long overestimate, Long uncertain,
                           Boolean criteriaMet, String status, String definitionVersion) {
    }

    /** MTTD(분위수 — 구간 아님). */
    public record Mttd(String scopeKind, String scopeKey, Long n,
                       Double p50Ms, Double p95Ms, String status, String definitionVersion) {
    }

    /** H2 가설(RID/HEADER 대 NONE). */
    public record H2(Long n, Long ridHeaderX, Double ridHeaderP, Double ridHeaderLo, Double ridHeaderHi,
                     Long noneX, Double noneP, Double noneLo, Double noneHi,
                     String status, String definitionVersion) {
    }

    /** 확정 스냅샷 1행(metric_snapshot). */
    public record Snapshot(String metricId, String scopeKind, String scopeKey,
                           Long x, Long n, Double p, Double lo, Double hi,
                           Double p50Ms, Double p95Ms, String status,
                           String definitionVersion, String snapshotRuleVersion) {
    }

    /** 시도(v_api_attempt). */
    public record Attempt(Long attemptId, String unitKey, String scenario, String techniqueId,
                          String attemptRole, String gtOutcome, String attackerVerdict, Boolean attackerMatch,
                          String verdict, String initialVerdict, String detectionStatus, Long mttdMs,
                          Double bestConfidence, Boolean lateDetection, String engineVersion,
                          OffsetDateTime decidedAt, String opId, String rid, String abilityId,
                          OffsetDateTime attackTime, String correlationSource) {
    }

    /** 연결 경보(v_api_alert_link). */
    public record AlertLink(String runId, Long attemptId, String rid, String ruleId, String control,
                            OffsetDateTime alertTime, String matchPath, Double confidence) {
    }

    /** /compare 1행(같은 definition_version 직접 join + newcombe_diff_ci). */
    public record CompareRow(String metricId, String scopeKind, String scopeKey, String definitionVersion,
                             Long x1, Long n1, Long x2, Long n2,
                             Double diff, Double lo, Double hi) {
    }
}
