package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.CorrelationEngine;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.VerdictEngine;
import com.capstone.vuln.correlation.VerdictRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.time.Duration;

/**
 * 측정 도구(OperationRunner) 빈 구성. UUID 설정키는 비밀이 아니라 application.yaml 에 두고,
 * Caldera 키만 환경변수(APP_CALDERA_APIKEY → app.caldera.api-key)에서 주입받는다.
 * 인증 방식은 기존 상관분석 클라이언트와 동일(헤더 KEY) — 새 인증 방식을 만들지 않는다.
 */
@Configuration
public class MeasureConfig {

    @Bean
    public CalderaOperations measureCalderaOperations(
            @Value("${app.caldera.api-url:http://caldera:8888}") String apiUrl,
            @Value("${app.caldera.api-key:}") String apiKey) {
        return new CalderaOperationsHttpClient(apiUrl, apiKey);
    }

    @Bean
    public OperationRunner operationRunner(
            CalderaOperations measureCalderaOperations,
            @Value("${app.measure.adversary-id}") String adversaryId,
            @Value("${app.measure.planner-id}") String plannerId,
            @Value("${app.measure.source-id}") String sourceId,
            @Value("${app.measure.group:red}") String group,
            @Value("${app.measure.poll-timeout-seconds:300}") long pollTimeoutSeconds,
            @Value("${app.measure.poll-interval-seconds:3}") long pollIntervalSeconds) {
        return new OperationRunner(
                measureCalderaOperations,
                adversaryId, plannerId, sourceId, group,
                Duration.ofSeconds(pollTimeoutSeconds),
                Duration.ofSeconds(pollIntervalSeconds),
                System::currentTimeMillis,
                duration -> Thread.sleep(duration.toMillis()));
    }

    // --- S3-5b-2a 수집 계층 ---

    @Bean
    public GtLogReader gtLogReader(
            @Value("${app.measure.gtlog.compose-file:docker/docker-compose.yml}") String composeFile,
            @Value("${app.measure.gtlog.project:security-lab}") String project,
            @Value("${app.measure.gtlog.service:target-web}") String service,
            @Value("${app.measure.gtlog.path:/var/log/target/attack.json.log}") String logPath) {
        return new GtLogReader(new DockerExecAttackLogSource(composeFile, project, service, logPath));
    }

    @Bean
    public AlertIndexReader alertIndexReader(
            @Value("${app.measure.indexer.url:https://127.0.0.1:9200}") String indexerUrl,
            @Value("${app.measure.indexer.index-pattern:wazuh-alerts-*}") String indexPattern,
            @Value("${app.measure.indexer.username:admin}") String username,
            @Value("${app.measure.indexer.password:}") String password,
            @Value("${app.measure.alert.rule-groups:vuln-webapp}") String ruleGroups,
            @Value("${app.measure.nids.rule-id:86601}") String nidsRuleId,
            @Value("${app.measure.indexer.ca-file:}") String caFile) {
        // S4-5: ca-file(인덱서 루트 CA PEM)을 주면 체인 검증 + 호스트명만 생략, 비우면 기존과 같은 trust-all(IndexerTls)
        Path ca = caFile == null || caFile.isBlank() ? null : Path.of(caFile.strip());
        return new AlertIndexReader(
                new IndexerAlertSearchSource(indexerUrl, indexPattern, username, password, ruleGroups, ca),
                IndexerAlertSearchSource.forRuleId(indexerUrl, indexPattern, username, password, nidsRuleId, ca));
    }

    /** S4-4 R14 b·c: eve.json 은 suricata_logs volume 안 — attack.json.log 와 같은 방식(docker compose exec cat, 읽기 전용) */
    @Bean
    public EveTelemetryReader eveTelemetryReader(
            @Value("${app.measure.gtlog.compose-file:docker/docker-compose.yml}") String composeFile,
            @Value("${app.measure.gtlog.project:security-lab}") String project,
            @Value("${app.measure.eve.service:suricata}") String service,
            @Value("${app.measure.eve.path:/var/log/suricata/eve.json}") String logPath) {
        return new EveTelemetryReader(new DockerExecAttackLogSource(composeFile, project, service, logPath));
    }

    @Bean
    public AttackerVerdictResolver attackerVerdictResolver(
            @Value("${app.caldera.api-url:http://caldera:8888}") String apiUrl,
            @Value("${app.caldera.api-key:}") String apiKey) {
        return new AttackerVerdictResolver(new CalderaOperationFactsSource(apiUrl, apiKey));
    }

    @Bean
    public MeasurementCollector measurementCollector(
            GtLogReader gtLogReader,
            AlertIndexReader alertIndexReader,
            AttackerVerdictResolver attackerVerdictResolver,
            EveTelemetryReader eveTelemetryReader,
            @Value("${app.measure.read-window-tail-seconds:30}") long readWindowTailSeconds) {
        return new MeasurementCollector(gtLogReader, alertIndexReader, attackerVerdictResolver,
                Duration.ofSeconds(readWindowTailSeconds), eveTelemetryReader);
    }

    /**
     * 측정 파이프라인 — VerdictRepository(= persistence.enabled=true)가 있을 때만 생성한다.
     * persistence OFF 면 이 빈은 없고(S3-5a 원칙: 측정 빠져도 취약 앱 기동 보장), 취약 앱은 그대로 뜬다.
     */
    @Bean
    @ConditionalOnBean(VerdictRepository.class)
    public MeasurementHarness measurementHarness(
            MeasurementCollector measurementCollector,
            CorrelationEngine correlationEngine,
            VerdictEngine verdictEngine,
            VerdictRepository verdictRepository,
            OperationResolver operationResolver,
            @Qualifier("validationDataSource") DataSource validationDataSource) {
        return new MeasurementHarness(measurementCollector, correlationEngine, verdictEngine, verdictRepository,
                operationResolver, new NidsCorrelator(NidsSidCatalog.V1_7), new NidsWindowRepository(validationDataSource));
    }

    // --- S3-5b-3 게이트 러너 (persistence 있을 때만) ---

    @Bean
    @ConditionalOnBean(VerdictRepository.class)
    public GateVerdictReader gateVerdictReader(
            @Qualifier("validationDataSource") DataSource validationDataSource) {
        return new GateVerdictReader(validationDataSource);
    }

    @Bean
    @ConditionalOnBean(VerdictRepository.class)
    public GateReportWriter gateReportWriter() {
        return new GateReportWriter();
    }

    // --- S4-1 run 차원 (persistence 있을 때만) ---

    /** git 상태·rules_digest 는 측정 JVM 작업 디렉터리(= 저장소 루트, gradle test) 기준 */
    @Bean
    @ConditionalOnBean(VerdictRepository.class)
    public MeasurementRunRecorder measurementRunRecorder(
            @Qualifier("validationDataSource") DataSource validationDataSource) {
        Path repoRoot = Path.of(".");
        return new MeasurementRunRecorder(new MeasurementRunRepository(validationDataSource),
                GitStateSource.cli(repoRoot), () -> RulesDigest.compute(repoRoot),
                AttemptManifest.ATTACK_VALIDATION_WEB, System::currentTimeMillis);
    }

    @Bean
    @ConditionalOnBean(VerdictRepository.class)
    public MeasurementCampaign measurementCampaign(
            OperationRunner operationRunner,
            MeasurementHarness measurementHarness,
            GateVerdictReader gateVerdictReader,
            MeasurementRunRecorder measurementRunRecorder,
            GateReportWriter gateReportWriter,
            @Value("${app.measure.observation-wait-seconds:30}") long observationWaitSeconds,
            @Value("${app.measure.report-dir:detections/measurements}") String reportDir) {
        return new MeasurementCampaign(
                operationRunner, measurementHarness, gateVerdictReader, measurementRunRecorder, gateReportWriter,
                Duration.ofSeconds(observationWaitSeconds), Path.of(reportDir),
                System::currentTimeMillis, duration -> Thread.sleep(duration.toMillis()));
    }
}
