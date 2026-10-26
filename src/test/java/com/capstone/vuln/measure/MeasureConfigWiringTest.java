package com.capstone.vuln.measure;

import com.capstone.vuln.correlation.CorrelationConfig;
import com.capstone.vuln.correlation.OperationResolver;
import com.capstone.vuln.correlation.VerdictRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

/**
 * Gap #6 교훈 — 컴포넌트 단위 테스트가 아니라 실제 빈 구성에서 하네스가 CorrelationConfig 의
 * OperationResolver 를 주입받는지 고정한다(정의만 있고 호출 0곳이던 상태의 재발 방지).
 */
class MeasureConfigWiringTest {

    @Test
    void measurementHarnessBeanIsWiredWithTheOperationResolverBean() {
        new ApplicationContextRunner()
                .withBean(VerdictRepository.class, () -> mock(VerdictRepository.class))
                .withBean("validationDataSource", DataSource.class, () -> mock(DataSource.class))
                .withUserConfiguration(CorrelationConfig.class, MeasureConfig.class)
                .withPropertyValues(
                        "app.measure.adversary-id=adv-test",
                        "app.measure.planner-id=planner-test",
                        "app.measure.source-id=source-test")
                .run(ctx -> {
                    MeasurementHarness harness = ctx.getBean(MeasurementHarness.class);
                    OperationResolver resolver = ctx.getBean(OperationResolver.class);
                    Object injected = ReflectionTestUtils.getField(harness, "operationResolver");
                    assertNotNull(injected, "하네스에 resolver 가 주입돼야 한다");
                    assertSame(resolver, injected);
                });
    }
}
