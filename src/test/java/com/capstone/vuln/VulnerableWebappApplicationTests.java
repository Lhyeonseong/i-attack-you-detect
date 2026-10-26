package com.capstone.vuln;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

// 앱 전체 컨텍스트를 띄우므로 PostgreSQL 이 필요하다. DB 에 연결할 수 없으면 실패 대신 skip 된다.
@SpringBootTest
@EnabledIf(value = "isDatabaseAvailable", disabledReason = "PostgreSQL 에 연결할 수 없어 컨텍스트 로드 테스트를 건너뜀")
class VulnerableWebappApplicationTests {

    @Test
    void contextLoads() {
    }

    // application.yaml 의 datasource 설정을 그대로 사용 (SPRING_DATASOURCE_URL 등 환경변수 override 포함)
    static boolean isDatabaseAvailable() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yaml"));

        StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().addLast(new PropertiesPropertySource("application", yaml.getObject()));

        String url = env.getProperty("spring.datasource.url");
        String username = env.getProperty("spring.datasource.username");
        String password = env.getProperty("spring.datasource.password");

        DriverManager.setLoginTimeout(3);
        try (Connection ignored = DriverManager.getConnection(url, username, password)) {
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

}
