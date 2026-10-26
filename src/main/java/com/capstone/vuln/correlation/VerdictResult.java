package com.capstone.vuln.correlation;

import java.time.Instant;
import java.util.List;

/**
 * Verdict 단위(SINGLE / BF_SEQUENCE / SPRAY_CAMPAIGN) 1건의 판정 결과
 *
 * detectionStatus·mttdMs 는 시나리오 탐지 기준으로 산출한 판정값이다. S4 지표는 이것만 쓴다.
 * (Correlation.detectionStatus/mttdMs 는 링크 기반 원시값 — S3-2 의미, 디버깅·Gap 분석용)
 *
 * - initialVerdict: 관찰기간(observedUntil) 안 alert 만으로 낸 판정
 * - verdict: 늦은 alert(late-alert-cap 이내로 링크된 것)까지 포함한 최종 판정 (결정4: 수정 허용 + 이력)
 * - lateDetection: 관찰기간 안에선 기준 미충족이었다가 늦은 alert 로 충족됨
 * - mttdMs: 기준을 충족시킨 alert 시각 − attackTime (늦어도 실제값. 집계 포함 여부는 S4 가 lateDetection 으로 분리)
 * - attackerVerdict: 정규화된 공격자 측 판정 (fact 누락이면 null) — Verdict 엔 영향 없음
 * - compromiseDetected: BF 단위에서 실패 기준 충족 후 120s 내 성공 alert 존재 (AN1276). BF 가 아니면 null
 * - unitKey: 저장 시 upsert 키 — SINGLE/BF_SEQUENCE = "unit:" + 멤버 correlationKey, SPRAY_CAMPAIGN = "spray:" + segmentId
 * - memberCorrelationIds: 묶인 Correlation 의 correlationKey (저장 시 verdict_member 의 correlation PK 로 바뀐다)
 */
public record VerdictResult(UnitType unitType,
                            String unitKey,
                            String scenario,
                            String techniqueId,
                            List<String> memberCorrelationIds,
                            Verdict verdict,
                            Verdict initialVerdict,
                            UncertainReason uncertainReason,
                            DetectionStatus detectionStatus,
                            GroundTruthOutcome gtOutcome,
                            GroundTruthOutcome attackerVerdict,
                            Boolean attackerMatch,
                            boolean overestimate,
                            double bestConfidence,
                            Long mttdMs,
                            boolean lateDetection,
                            Boolean compromiseDetected,
                            Instant compromiseAlertTime,
                            int sprayAccountCount) {
}
