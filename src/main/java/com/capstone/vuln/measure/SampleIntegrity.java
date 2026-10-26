package com.capstone.vuln.measure;

/**
 * R10 표본 무결성(SRM 대응, ADR-S4-01 v1.2) 결과 — 판정 원천은 validation.v_run_integrity 뷰 하나다(Java 재계산 없음).
 * VALID = CLOSED ∧ ATTACK·CONTROL 실제 = 기대, INVALID = CLOSED ∧ (불일치 ∨ 기대 없음), INCOMPLETE = OPEN.
 * 지표는 VALID run 에서만 산출한다.
 */
public final class SampleIntegrity {

    public enum Status { VALID, INVALID, INCOMPLETE }

    /**
     * @param reason VALID 면 null, 아니면 "코드 (expected a, actual b)" — 코드는 뷰 r10_reason 그대로
     *               (OPEN → EXPECTED_MISSING → ATTACK_MISMATCH → CONTROL_MISMATCH 중 첫 해당)
     */
    public record Result(Status status, String reason) {

        @Override
        public String toString() {
            return reason == null ? status.name() : status + " " + reason;
        }
    }

    private SampleIntegrity() {
    }

    /** v_run_integrity 1행 → Result */
    static Result fromView(String r10Status, String r10Reason, Integer expectedAttempts, Integer expectedControls,
                           long actualAttack, long actualControl) {
        Status status = Status.valueOf(r10Status);
        if (r10Reason == null) {
            return new Result(status, null);
        }
        return new Result(status, r10Reason
                + " (expected attack=" + expectedAttempts + " control=" + expectedControls
                + ", actual attack=" + actualAttack + " control=" + actualControl + ")");
    }
}
