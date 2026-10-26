package com.capstone.vuln.ssrf;

/**
 * SsrfValidator 입력 (ValidationContext.payload)
 * - resultType: PreviewController가 산출한 fetch 결과 (FETCHED / BLOCKED / ERROR)
 * - internalTarget: 요청 URL의 host가 내부 전용 대역(메타데이터/loopback/link-local/사설)인지
 * - sentinelReached: 응답 본문에 Mock IMDS sentinel("MOCK-IMDS-DO-NOT-USE")이 포함됐는지 (boolean 만, 본문 원문은 담지 않는다)
 * - host: 분류 근거가 된 host 문자열 (비밀값 아님, 공격자 입력). 응답 본문/자격증명 원문은 절대 담지 않는다
 * - responseCode / bodyLength: 응답 메타데이터만
 */
public record SsrfInput(
        ResultType resultType,
        boolean internalTarget,
        boolean sentinelReached,
        String host,
        int responseCode,
        long bodyLength) {

    public enum ResultType {
        /** 서버가 아웃바운드 요청을 보내 응답을 받음 */
        FETCHED,
        /** 화이트리스트/스킴 가드가 아웃바운드 요청을 차단함 */
        BLOCKED,
        /** 연결 오류·타임아웃·호스트 불명 등 판정 모호 */
        ERROR
    }

    public static SsrfInput fetched(boolean internalTarget, boolean sentinelReached,
                                    String host, int responseCode, long bodyLength) {
        return new SsrfInput(ResultType.FETCHED, internalTarget, sentinelReached, host, responseCode, bodyLength);
    }

    public static SsrfInput blocked(String host) {
        return new SsrfInput(ResultType.BLOCKED, false, false, host, 0, 0);
    }

    public static SsrfInput error(String host) {
        return new SsrfInput(ResultType.ERROR, false, false, host, 0, 0);
    }
}
