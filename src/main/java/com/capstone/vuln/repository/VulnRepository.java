package com.capstone.vuln.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class VulnRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * [VULNERABLE] Raw SQL 실행 메서드
     * PreparedStatement 우회용 — 의도적으로 위험
     * SQLi 공격 재현을 위해 문자열 결합 쿼리를 그대로 실행
     */
    public List<Map<String, Object>> executeRawQuery(String sql) {
        return jdbcTemplate.queryForList(sql);
    }
}