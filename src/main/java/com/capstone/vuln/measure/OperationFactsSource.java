package com.capstone.vuln.measure;

/** Caldera operation JSON(chain[].facts 포함) 원문 공급 — 테스트는 고정 샘플, 운영은 Caldera HTTP(주입). */
@FunctionalInterface
public interface OperationFactsSource {
    String fetchOperationJson(String opId);
}
