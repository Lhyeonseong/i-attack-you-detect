package com.capstone.vuln.correlation;

import java.time.Instant;

/**
 * Caldera operation chain 의 링크 1개 (/api/v2/operations → chain[])
 * finish 가 null 이면 아직 실행 중
 */
public record OperationLink(String opId, String paw, String abilityId, Instant decide, Instant finish) {

    /** decide/finish 는 초 단위로 절삭돼 오므로 finish 는 +1s 까지 포함한다 */
    public boolean covers(Instant time) {
        return !time.isBefore(decide)
                && (finish == null || time.isBefore(finish.plusSeconds(1)));
    }
}
