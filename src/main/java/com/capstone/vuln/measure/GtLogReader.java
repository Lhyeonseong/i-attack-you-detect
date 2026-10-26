package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.AlertEvent;
import com.capstone.vuln.correlation.AttackEvent;
import com.capstone.vuln.correlation.AttemptRole;
import com.capstone.vuln.correlation.CorrelationKey;
import com.capstone.vuln.correlation.GroundTruthOutcome;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.capstone.vuln.measure.MeasureJson.text;

/**
 * 앱 OCSF 로그(attack.json.log) → op 창의 AttackEvent 리스트 (수집기 1).
 *
 * <p>필드 매핑(S3-2 실측, 앱 로그는 최상위 — data.* 중첩 아님):
 * time(epoch ms)→attackTime, rid, correlation.op_id(=paw)/ability_id, validation.outcome→gt,
 * validation.technique_id, src_endpoint.ip, http_request.url.path(→scenario), http_request.args→username.
 *
 * <p>읽기 창 [windowStart, windowEndInclusive] 밖 라인은 제외. correlation.op_id(=paw)가 없는(Caldera
 * 미태깅) 라인도 제외 — 측정 이벤트는 모두 HEADER 태깅이며, 창 안 수동 노이즈를 배제한다(op 단위 격리 전제).
 *
 * <p>S4-1: rid 별 시도 역할(ATTACK/CONTROL)도 함께 낸다 — manifest + 요청 대상(http_request.args)만으로
 * 판별(정답지 쪽, B안). AttackEvent(엔진 입력)는 바꾸지 않는다.
 */
public class GtLogReader {

    /** 창 1개 읽기 결과 — events: 엔진 입력, roles: rid → 시도 역할, args: rid → http_request.args (S4-4 R14 c URL 비교) */
    public record GtWindow(List<AttackEvent> events, Map<String, AttemptRole> roles, Map<String, String> args) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AttackLogSource source;
    private final AttemptManifest manifest;

    public GtLogReader(AttackLogSource source) {
        this(source, AttemptManifest.ATTACK_VALIDATION_WEB);
    }

    public GtLogReader(AttackLogSource source, AttemptManifest manifest) {
        this.source = source;
        this.manifest = manifest;
    }

    public List<AttackEvent> read(Instant windowStart, Instant windowEndInclusive) {
        return readWindow(windowStart, windowEndInclusive).events();
    }

    public GtWindow readWindow(Instant windowStart, Instant windowEndInclusive) {
        List<AttackEvent> events = new ArrayList<>();
        Map<String, AttemptRole> roles = new LinkedHashMap<>();
        Map<String, String> requestArgs = new LinkedHashMap<>();
        for (String raw : source.read().split("\n")) {
            String line = raw.trim();
            if (line.isEmpty()) {
                continue;
            }
            JsonNode o;
            try {
                o = MAPPER.readTree(line);
            } catch (Exception e) {
                continue;
            }
            JsonNode timeNode = o.path("time");
            if (!timeNode.canConvertToLong()) {
                continue;
            }
            Instant attackTime = Instant.ofEpochMilli(timeNode.asLong());
            if (attackTime.isBefore(windowStart) || attackTime.isAfter(windowEndInclusive)) {
                continue;
            }
            JsonNode correlation = o.path("correlation");
            String paw = text(correlation.path("op_id"));
            if (paw == null) {
                continue; // Caldera 미태깅(수동) 라인 제외
            }
            String abilityId = text(correlation.path("ability_id"));
            String rid = text(o.path("rid"));
            JsonNode request = o.path("http_request");
            String path = text(request.path("url").path("path"));
            String srcIp = text(o.path("src_endpoint").path("ip"));
            String args = text(request.path("args"));
            String username = MeasureJson.normalize(AlertEvent.usernameFromArgs(args));
            String technique = text(o.path("validation").path("technique_id"));
            GroundTruthOutcome gt = GroundTruthOutcome.fromValidation(text(o.path("validation").path("outcome")));

            events.add(new AttackEvent(
                    new CorrelationKey(paw, abilityId, rid),
                    ScenarioMapping.scenarioFor(path),
                    technique,
                    attackTime,
                    srcIp,
                    path,
                    username,
                    gt));
            if (rid != null) {
                roles.put(rid, manifest.roleOf(abilityId, args));
                if (args != null) {
                    requestArgs.put(rid, args);
                }
            }
        }
        return new GtWindow(events, roles, requestArgs);
    }
}
