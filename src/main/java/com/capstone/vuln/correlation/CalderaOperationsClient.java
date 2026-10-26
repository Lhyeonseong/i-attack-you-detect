package com.capstone.vuln.correlation;

import java.util.List;

/**
 * Caldera operation 링크 조회. 실패 시 RuntimeException 을 던진다 (OperationResolver 가 graceful 처리)
 */
@FunctionalInterface
public interface CalderaOperationsClient {

    List<OperationLink> fetchLinks();
}
