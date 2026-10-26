package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.CorrelationConfig;
import com.capstone.vuln.correlation.ValidationPersistenceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 본측정 실행 엔트리포인트 — 재현성/test evidence 를 위해 리포에 둔다(삭제하지 않음).
 *
 * <p>기본 build/CI 에서는 절대 돌지 않는다: {@code RUN_CALDERA_MEASURE=1} 일 때만 실행.
 * persistence 는 이 측정 JVM 에서만 enabled + validation datasource(127.0.0.1:5433, validation_rw)로
 * 켠다 — 컨테이너 플래그 APP_VALIDATION_PERSISTENCE_ENABLED 는 건드리지 않는다.
 *
 * <p>tmux 실행(사람이 직접):
 * <pre>
 * RUN_CALDERA_MEASURE=1 MEASURE_N=20 MEASURE_LABEL=... \
 *   APP_CALDERA_APIKEY=... INDEXER_USERNAME=... INDEXER_PASSWORD=... \
 *   POSTGRES_DB=... VALIDATION_DB_PASSWORD=... \
 *   ./gradlew cleanTest test --tests 'com.capstone.vuln.measure.CampaignRunnerIT' -i
 * </pre>
 * MEASURE_N 기본 20, MEASURE_LABEL = measurement_run.label (필수, 기본값 없음 — 없으면 실패). 리포트는
 * detections/measurements/gate-report-&lt;iso&gt;.md(.json) 에 생성.
 * S4-1: 캠페인 1회 = measurement_run 1개, 게이트는 그 run 만 집계하므로 truncate 기본 OFF
 * (켜면 백필된 S3 baseline 까지 지운다). 꼭 필요할 때만 MEASURE_TRUNCATE=1.
 * 실행 절차 예: detections/measurements/RUNBOOK-S4-1b-smoke.md
 */
@SpringBootTest(classes = {CorrelationConfig.class, ValidationPersistenceConfig.class, MeasureConfig.class})
@TestPropertySource(properties = {
        "app.caldera.api-url=http://127.0.0.1:8888",
        "app.validation.persistence.enabled=true",
        "app.validation.datasource.url=jdbc:postgresql://127.0.0.1:5433/${POSTGRES_DB}?currentSchema=validation",
        "app.validation.datasource.username=validation_rw",
        "app.validation.datasource.password=${VALIDATION_DB_PASSWORD}"
})
@EnabledIfEnvironmentVariable(named = "RUN_CALDERA_MEASURE", matches = "1")
class CampaignRunnerIT {

    @Autowired
    private MeasurementCampaign campaign;

    @Test
    void measure() {
        int n = Integer.parseInt(System.getenv().getOrDefault("MEASURE_N", "20"));
        boolean truncate = "1".equals(System.getenv("MEASURE_TRUNCATE"));
        String label = requireLabel(System.getenv());
        System.out.println("MEASURE>> starting campaign run label=" + label + " n=" + n + " truncate=" + truncate);
        GateReport report = campaign.run(label, n, truncate);
        System.out.println("MEASURE>> done overall=" + report.overall()
                + " totalSamples=" + report.totalSamples());
        assertNotNull(report, "게이트 리포트가 생성돼야 함");
    }

    /** measurement_run.label — 측정마다 의도를 남기도록 기본값을 두지 않는다 */
    static String requireLabel(Map<String, String> env) {
        String label = env.get("MEASURE_LABEL");
        if (label == null || label.isBlank()) {
            throw new IllegalStateException("MEASURE_LABEL 필요 (measurement_run.label, 기본값 없음)");
        }
        return label;
    }
}
