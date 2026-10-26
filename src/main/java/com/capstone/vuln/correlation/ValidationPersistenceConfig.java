package com.capstone.vuln.correlation;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * validation schema 영속화 — app.validation.persistence.enabled=true 일 때만 (기본 false)
 *
 * validationDataSource 는 별도 role(validation_rw) 접속이며 defaultCandidate=false 로 등록한다.
 * 그래야 취약 앱의 자동설정 DataSource·JdbcTemplate·sql.init 이 그대로 유지되고, 이 DataSource 는
 * @Qualifier("validationDataSource") 로만 주입된다.
 */
@Configuration
@ConditionalOnProperty(name = "app.validation.persistence.enabled", havingValue = "true")
public class ValidationPersistenceConfig {

    @Bean(defaultCandidate = false)
    public DataSource validationDataSource(
            @Value("${app.validation.datasource.url}") String url,
            @Value("${app.validation.datasource.username}") String username,
            @Value("${app.validation.datasource.password}") String password) {
        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setPoolName("validation");
        dataSource.setJdbcUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);
        dataSource.setMaximumPoolSize(2);
        return dataSource;
    }

    @Bean
    public VerdictRepository verdictRepository(@Qualifier("validationDataSource") DataSource validationDataSource) {
        ValidationSchemaMigrator.migrate(validationDataSource);
        return new VerdictRepository(validationDataSource);
    }
}
