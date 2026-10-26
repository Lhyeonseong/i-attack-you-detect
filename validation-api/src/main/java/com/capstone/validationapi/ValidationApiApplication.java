package com.capstone.validationapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * validation-api (ADR-S4-02 S4-6) — 측정 "확정 당시" 지표를 읽기 전용(validation_ro)으로 제공하는 조회 서비스.
 * 마이그레이션·쓰기 없음(JdbcClient·읽기 전용 트랜잭션). 대시보드 정적 자원도 같은 출처에서 서빙(D9).
 */
@SpringBootApplication
@EnableConfigurationProperties(ValidationApiProperties.class)
public class ValidationApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(ValidationApiApplication.class, args);
    }
}
