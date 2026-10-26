package com.capstone.vuln.correlation;

import org.flywaydb.core.Flyway;

import javax.sql.DataSource;

/**
 * validation schema 전용 Flyway 마이그레이션 (classpath:db/validation)
 *
 * 취약 앱 datasource 에는 절대 돌리지 않는다 — Boot 4 의 Flyway 자동설정(spring-boot-starter-flyway)은 넣지 않고
 * (spring.flyway.enabled=false 도 유지) validation datasource 로만 여기서 직접 실행한다. schema 는 부트스트랩 SQL(db/bootstrap/validation_role.sql)이 만든다.
 */
public final class ValidationSchemaMigrator {

    static final String SCHEMA = "validation";

    private ValidationSchemaMigrator() {
    }

    public static void migrate(DataSource validationDataSource) {
        Flyway.configure()
                .dataSource(validationDataSource)
                .schemas(SCHEMA)
                .defaultSchema(SCHEMA)
                .createSchemas(false)
                .locations("classpath:db/validation")
                .load()
                .migrate();
    }
}
