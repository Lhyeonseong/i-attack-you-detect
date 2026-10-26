package com.capstone.vuln.measure;

/** 앱 OCSF 로그(attack.json.log) 원문 공급 — 테스트는 고정 샘플, 운영은 docker exec cat (주입). */
@FunctionalInterface
public interface AttackLogSource {
    String read();
}
