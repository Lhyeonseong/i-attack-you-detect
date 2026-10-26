package com.capstone.vuln.measure;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * measurement_run.rules_digest — 측정에 쓰인 탐지 룰·공격 정의 파일의 sha256 (저장소 기준, 결정적).
 *
 * <p>대상(실제 로드되는 파일만): Wazuh vuln_rules.xml / Suricata local.rules(compose -S 로 이것만 로드) /
 * Caldera adversary yml + 그 adversary 의 atomic_ordering 이 참조하는 ability 파일.
 * 저장소 파일 해시이며 컨테이너 런타임에 실제 로드된 룰과 같다는 증명은 아니다(단일 파일 bind-mount 갱신 지연 가능).
 */
public record RulesDigest(String wazuhRules, String suricataRules, String calderaAdversary,
                          SortedMap<String, String> calderaAbilities) {

    public static final Path WAZUH_RULES = Path.of("docker/config/wazuh_manager/rules/vuln_rules.xml");
    public static final Path SURICATA_RULES = Path.of("docker/config/suricata/local.rules");
    public static final Path CALDERA_ADVERSARY = Path.of("docker/config/caldera/adversaries/attack_validation_web.yml");
    public static final Path CALDERA_ABILITIES_DIR = Path.of("docker/config/caldera/abilities");

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern LIST_ITEM = Pattern.compile("^-\\s+['\"]?([^'\"\\s]+)['\"]?\\s*$");

    public static RulesDigest compute(Path repoRoot) {
        Path adversary = repoRoot.resolve(CALDERA_ADVERSARY);
        List<String> ordering = atomicOrdering(adversary);
        SortedMap<String, String> abilities = new TreeMap<>();
        abilityFiles(repoRoot.resolve(CALDERA_ABILITIES_DIR), ordering)
                .forEach((id, file) -> abilities.put(id, sha256(file)));
        return new RulesDigest(
                sha256(repoRoot.resolve(WAZUH_RULES)),
                sha256(repoRoot.resolve(SURICATA_RULES)),
                sha256(adversary),
                abilities);
    }

    /** {"wazuh_rules":…, "suricata_rules":…, "caldera_adversary":…, "caldera_abilities":{id:sha256}} (키 순서 고정) */
    public String toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("wazuh_rules", wazuhRules);
        json.put("suricata_rules", suricataRules);
        json.put("caldera_adversary", calderaAdversary);
        json.put("caldera_abilities", calderaAbilities);
        try {
            return MAPPER.writeValueAsString(json);
        } catch (JacksonException e) {
            throw new IllegalStateException(e);
        }
    }

    /** adversary yml 의 atomic_ordering 목록 (최상위 키 아래 "- <id>" 줄) */
    static List<String> atomicOrdering(Path adversary) {
        List<String> ids = new ArrayList<>();
        boolean inOrdering = false;
        for (String line : readLines(adversary)) {
            if (line.startsWith("atomic_ordering:")) {
                inOrdering = true;
                continue;
            }
            if (!inOrdering) {
                continue;
            }
            Matcher m = LIST_ITEM.matcher(line);
            if (m.matches()) {
                ids.add(m.group(1));
            } else if (!line.isBlank()) {
                break;
            }
        }
        if (ids.isEmpty()) {
            throw new IllegalStateException("atomic_ordering 이 비어 있음: " + adversary);
        }
        return ids;
    }

    /** ability id → 정의 파일 (최상위 "- id: <id>"). 없거나 2개 이상이면 실패 */
    static Map<String, Path> abilityFiles(Path abilitiesDir, List<String> abilityIds) {
        Map<String, Path> found = new TreeMap<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(abilitiesDir)) {
            files = walk.filter(p -> p.toString().endsWith(".yml")).sorted().toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        for (Path file : files) {
            for (String line : readLines(file)) {
                for (String id : abilityIds) {
                    if (line.matches("^-\\s+id:\\s*['\"]?" + Pattern.quote(id) + "['\"]?\\s*$")) {
                        Path prev = found.put(id, file);
                        if (prev != null) {
                            throw new IllegalStateException("ability " + id + " 정의 중복: " + prev + ", " + file);
                        }
                    }
                }
            }
        }
        for (String id : abilityIds) {
            if (!found.containsKey(id)) {
                throw new IllegalStateException("ability 정의 파일 없음: " + id);
            }
        }
        return found;
    }

    private static List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file);
        } catch (IOException e) {
            throw new IllegalStateException("읽기 실패: " + file, e);
        }
    }

    private static String sha256(Path file) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        } catch (IOException e) {
            throw new IllegalStateException("읽기 실패: " + file, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
