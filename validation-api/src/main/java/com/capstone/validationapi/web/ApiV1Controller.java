package com.capstone.validationapi.web;

import com.capstone.validationapi.ValidationApiProperties;
import com.capstone.validationapi.dto.ApiDtos.CompareRow;
import com.capstone.validationapi.dto.ApiDtos.Meta;
import com.capstone.validationapi.dto.ApiDtos.NavigatorVersions;
import com.capstone.validationapi.dto.ApiDtos.Run;
import com.capstone.validationapi.error.ApiExceptions.BadRequestException;
import com.capstone.validationapi.error.ApiExceptions.DefinitionMismatchException;
import com.capstone.validationapi.error.ApiExceptions.NotFoundException;
import com.capstone.validationapi.error.ApiExceptions.NotValidRunException;
import com.capstone.validationapi.repo.ValidationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * ADR-S4-02 D4: GET 전용 /api/v1/*. 바인딩 파라미터·허용 목록·limit 상한. 비-VALID run 지표는 409.
 * 구간·차이는 DB(뷰/함수) 값 그대로 — 재계산 없음.
 */
@RestController
@RequestMapping("/api/v1")
public class ApiV1Controller {

    private static final Set<String> METRIC_NAMES =
            Set.of("rates", "correlation", "h2", "mttd", "coverage", "attacker");
    private static final Set<String> VERDICTS = Set.of("SUCCEEDED_MISSED", "SUCCEEDED_DETECTED",
            "SUCCEEDED_BLOCKED", "BLOCKED", "FAILED_DETECTED", "FAILED_UNSEEN", "UNCERTAIN");

    private final ValidationRepository repo;
    private final NavigatorService navigator;
    private final ValidationApiProperties props;
    private final ImdsLogService imdsLog;

    public ApiV1Controller(ValidationRepository repo, NavigatorService navigator,
                           ValidationApiProperties props, ImdsLogService imdsLog) {
        this.repo = repo;
        this.navigator = navigator;
        this.props = props;
        this.imdsLog = imdsLog;
    }

    @GetMapping("/meta")
    public Meta meta() {
        return new Meta(repo.definitionVersions(), repo.latestDefinitionVersion(), repo.runCount(),
                new NavigatorVersions("20.0", "5.3.2", "4.5"));
    }

    @GetMapping("/runs")
    public List<Run> runs() {
        return repo.runs();
    }

    @GetMapping("/runs/{runId}")
    public Run run(@PathVariable UUID runId) {
        Run r = repo.findRun(runId);
        if (r == null) {
            throw new NotFoundException("run 없음");
        }
        return r;
    }

    /** definition_version 필터(기본 최신), 철회 제외. 선택적 run_id. */
    @GetMapping("/snapshot")
    public List<?> snapshot(@RequestParam(name = "definition_version", required = false) String definitionVersion,
                            @RequestParam(name = "run_id", required = false) UUID runId) {
        String dv = definitionVersion;
        if (dv == null || dv.isBlank()) {
            // 기본 최신: 문자열 max 아님 — 가장 최근 snapshot_at 기준(run 지정 시 그 run)
            dv = (runId != null) ? repo.latestDefinitionVersionForRun(runId) : repo.latestDefinitionVersion();
        }
        if (dv == null) {
            return List.of();
        }
        return repo.snapshot(dv, runId);
    }

    /** name 은 허용 목록. 비-VALID run → 409. */
    @GetMapping("/runs/{runId}/metrics/{name}")
    public Object metrics(@PathVariable UUID runId, @PathVariable String name) {
        if (!METRIC_NAMES.contains(name)) {
            throw new BadRequestException("허용되지 않은 지표 이름: " + name);
        }
        requireValid(runId);
        return switch (name) {
            case "rates" -> repo.rates(runId);
            case "coverage" -> repo.coverage(runId);
            case "correlation" -> repo.correlation(runId);
            case "attacker" -> repo.attacker(runId);
            case "mttd" -> repo.mttd(runId);
            case "h2" -> repo.h2(runId);
            default -> throw new BadRequestException("지표 이름: " + name);
        };
    }

    @GetMapping("/runs/{runId}/attempts")
    public List<?> attempts(@PathVariable UUID runId,
                            @RequestParam(required = false) String verdict,
                            @RequestParam(required = false) Integer limit) {
        if (verdict != null && !VERDICTS.contains(verdict)) {
            throw new BadRequestException("허용되지 않은 verdict: " + verdict);
        }
        if (repo.integrityStatus(runId) == null) {
            throw new NotFoundException("run 없음");
        }
        return repo.attempts(runId, verdict, clampLimit(limit));
    }

    /** 화면④ 연결 경보(v_api_alert_link). username·src_ip 미노출. */
    @GetMapping("/runs/{runId}/alert-links")
    public List<?> alertLinks(@PathVariable UUID runId, @RequestParam(required = false) Integer limit) {
        if (repo.integrityStatus(runId) == null) {
            throw new NotFoundException("run 없음");
        }
        return repo.alertLinks(runId, clampLimit(limit));
    }

    /** 선택한 측정 시간 구간에 Mock IMDS sentinel 경로까지 실제 도달한 HTTP 요청 수. */
    @GetMapping("/runs/{runId}/imds-requests")
    public Map<String, Long> imdsRequests(@PathVariable UUID runId) {
        Run r = repo.findRun(runId);
        if (r == null) {
            throw new NotFoundException("run 없음");
        }
        long count = imdsLog.countRequests(r.startedAt(), r.endedAt());
        return Map.of("request_count", count);
    }

    /** 같은 definition_version 행끼리 직접 join + newcombe_diff_ci. 공유 정의 없으면 409. */
    @GetMapping("/compare")
    public Map<String, Object> compare(@RequestParam UUID before, @RequestParam UUID after) {
        List<String> shared = repo.sharedDefinitionVersions(before, after);
        if (shared.isEmpty()) {
            throw new DefinitionMismatchException("before·after 가 공유하는 definition_version 이 없습니다");
        }
        List<CompareRow> rows = repo.compare(before, after);
        return Map.of(
                "before", before.toString(),
                "after", after.toString(),
                "shared_definition_versions", shared,
                "rows", rows);
    }

    /** ATT&CK Navigator 레이어(detection|visibility). 비-VALID run → 409. */
    @GetMapping("/navigator-layer")
    public Map<String, Object> navigatorLayer(@RequestParam(name = "run_id") UUID runId,
                                              @RequestParam String layer) {
        if (!"detection".equals(layer) && !"visibility".equals(layer)) {
            throw new BadRequestException("layer 는 detection|visibility 만");
        }
        requireValid(runId);
        String dv = repo.latestDefinitionVersionForRun(runId);
        return navigator.layer(runId, layer, dv);
    }

    // ── helpers ──────────────────────────────────────────────────────────────
    private void requireValid(UUID runId) {
        String status = repo.integrityStatus(runId);
        if (status == null) {
            throw new NotFoundException("run 없음");
        }
        if (!"VALID".equals(status)) {
            throw new NotValidRunException("run 무결성 상태: " + status + " (지표 미반환)");
        }
    }

    private int clampLimit(Integer limit) {
        int max = props.maxLimit();
        if (limit == null) {
            return props.defaultLimit();
        }
        if (limit < 1 || limit > max) {
            throw new BadRequestException("limit 는 1~" + max + " 범위");
        }
        return limit;
    }
}
