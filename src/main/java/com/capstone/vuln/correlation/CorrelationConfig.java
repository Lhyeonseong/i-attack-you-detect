package com.capstone.vuln.correlation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
public class CorrelationConfig {

    /**
     * 늦은 alert 상한(초). 0 이하 = 비활성(상한 없음).
     * S4 Ingestion Lag 실측(p99 × 안전계수)으로 확정 예정 — 그 전엔 임의 값을 두지 않는다.
     */
    @Bean
    public CorrelationEngine correlationEngine(
            @Value("${app.correlation.late-alert-cap-seconds:0}") long lateAlertCapSeconds,
            @Value("${app.correlation.spray-account-threshold:" + CorrelationEngine.DEFAULT_SPRAY_ACCOUNT_THRESHOLD + "}")
            int sprayAccountThreshold) {
        return new CorrelationEngine(lateAlertCapSeconds > 0 ? Duration.ofSeconds(lateAlertCapSeconds) : null,
                sprayAccountThreshold);
    }

    /** 스프레이 임계: AN1277 조정값, 표준 수치 없음, 잠정 (CorrelationEngine 과 같은 값을 써야 한다) */
    @Bean
    public VerdictEngine verdictEngine(
            @Value("${app.correlation.spray-account-threshold:" + CorrelationEngine.DEFAULT_SPRAY_ACCOUNT_THRESHOLD + "}")
            int sprayAccountThreshold) {
        return new VerdictEngine(sprayAccountThreshold);
    }

    /** 실제 URL·키는 .env 로 주입 (APP_CALDERA_APIURL / APP_CALDERA_APIKEY) */
    @Bean
    public OperationResolver operationResolver(
            @Value("${app.caldera.api-url:http://caldera:8888}") String apiUrl,
            @Value("${app.caldera.api-key:}") String apiKey) {
        return new OperationResolver(new CalderaOperationsHttpClient(apiUrl, apiKey));
    }
}
