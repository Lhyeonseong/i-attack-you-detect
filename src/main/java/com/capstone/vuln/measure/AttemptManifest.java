package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AttemptRole;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 시도 단위 manifest (ADR-S4-01 v1.1 R6·R10) — operation 1회에 ability 별로 몇 건의 공격 시도·대조 요청이 나오는가.
 *
 * <p>코드 상수로 둔다: 정답지 쪽 기대값이라 탐지 설정(yml)과 분리하고, ability 정의와의 일치는
 * AttemptManifestTest 가 실제 adversary·ability yml 로 검사한다. ability 파일이 바뀌면 rules_digest 도 바뀐다.
 *
 * <p>대조군 판별은 정답지 쪽 정보만 쓴다(B안): ability_id + 앱 로그의 요청 대상(http_request.args 의 url).
 * 탐지 결과(alert)는 참조하지 않는다.
 */
public final class AttemptManifest {

    /**
     * @param controlTarget 대조 요청의 url 파라미터 값 (대조군 없는 ability 는 null)
     */
    public record Entry(String abilityId, String scenario, int attackUnits, int controlUnits, String controlTarget) {
    }

    /** [V] ATT&CK Validation — Web (adv-attack-validation-web-001) */
    public static final AttemptManifest ATTACK_VALIDATION_WEB = new AttemptManifest(List.of(
            new Entry("e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c", "SQLI", 1, 0, null),
            new Entry("a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60", "SSRF", 2, 1, "http://example.com/"),
            new Entry("c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b", "PATH_TRAVERSAL", 3, 0, null),
            new Entry("7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d", "BRUTE_FORCE", 1, 0, null))); // R6: BF = 시퀀스 1건

    private final Map<String, Entry> byAbility = new LinkedHashMap<>();

    public AttemptManifest(List<Entry> entries) {
        for (Entry e : entries) {
            byAbility.put(e.abilityId(), e);
        }
    }

    public Entry entry(String abilityId) {
        return byAbility.get(abilityId);
    }

    public List<String> abilityIds() {
        return List.copyOf(byAbility.keySet());
    }

    public int attacksPerOperation() {
        return byAbility.values().stream().mapToInt(Entry::attackUnits).sum();
    }

    public int controlsPerOperation() {
        return byAbility.values().stream().mapToInt(Entry::controlUnits).sum();
    }

    /** 요청 1건의 역할 — 대조군을 정의한 ability 이고 url 파라미터가 그 대조 대상과 같을 때만 CONTROL */
    public AttemptRole roleOf(String abilityId, String requestArgs) {
        Entry e = abilityId == null ? null : byAbility.get(abilityId);
        if (e == null || e.controlTarget() == null || requestArgs == null) {
            return AttemptRole.ATTACK;
        }
        for (String pair : requestArgs.split("&")) {
            if (pair.equals("url=" + e.controlTarget())) {
                return AttemptRole.CONTROL;
            }
        }
        return AttemptRole.ATTACK;
    }
}
