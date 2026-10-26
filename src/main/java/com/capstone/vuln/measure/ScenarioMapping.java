package com.capstone.vuln.measure;

import com.capstone.vuln.attack.AttackScenario;

import java.util.Map;

/**
 * 앱 엔드포인트 경로 → scenario 라벨 (결정 A). 매핑을 한 곳에 모은다.
 * 미등록 경로는 조용히 오분류하지 않고 {@link #UNKNOWN} 으로 둔다.
 *
 * <p>scenario 문자열은 생산 enum {@link AttackScenario} 이름과 동일하게 쓴다(SQLI/PATH_TRAVERSAL/
 * BRUTE_FORCE/SSRF) — 로그에 scenario 필드가 없고 SQLi·SSRF·PT 가 모두 T1190 이라 technique_id 로는
 * 구분되지 않으므로 url.path 로 판별한다.
 */
public final class ScenarioMapping {

    public static final String UNKNOWN = "UNKNOWN";

    private static final Map<String, AttackScenario> BY_PATH = Map.of(
            "/api/products/search", AttackScenario.SQLI,
            "/api/files/download", AttackScenario.PATH_TRAVERSAL,
            "/api/preview", AttackScenario.SSRF,
            "/api/auth/login", AttackScenario.BRUTE_FORCE);

    private ScenarioMapping() {
    }

    /** 경로 → scenario 이름. 미등록·null 이면 "UNKNOWN". */
    public static String scenarioFor(String path) {
        AttackScenario scenario = path == null ? null : BY_PATH.get(path);
        return scenario == null ? UNKNOWN : scenario.name();
    }
}
