package com.capstone.vuln;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;

@Component
public class DBTest {

    @Autowired
    private DataSource dataSource;

    @PostConstruct
    public void testConnection() {

        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("DB 연결 성공: " + conn);
        } catch (Exception e) {
            System.out.println("DB 연결 실패");
            e.printStackTrace();
        }
    }
}