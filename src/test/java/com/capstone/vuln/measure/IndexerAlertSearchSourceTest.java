package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 질의 바디 회귀 — 커스텀 탐지룰 그룹(vuln-webapp)만 통과시키고 Wazuh 내장 rule 1002 를 끌어오던
 * rule.id prefix 질의를 쓰지 않음을 검증(노이즈 재발 방지).
 */
class IndexerAlertSearchSourceTest {

    @Test
    void query_filters_by_rule_groups_not_rule_id_prefix() {
        String body = IndexerAlertSearchSource.searchBody(1000L, 2000L, "vuln-webapp");

        // vuln-webapp 그룹 term 으로 거른다
        assertTrue(body.contains("\"term\":{\"rule.groups\":\"vuln-webapp\"}"),
                "rule.groups term 필터가 있어야 함");
        // 내장 1002 를 끌어오던 rule.id prefix 질의는 더 이상 쓰지 않는다
        assertFalse(body.contains("prefix"), "rule.id prefix 질의는 제거돼야 함");
        assertFalse(body.contains("rule.id"), "rule.id 필터는 쓰지 않는다");
        assertFalse(body.contains("1002"), "내장 rule 1002 를 유발하던 prefix 값이 없어야 함");
    }

    @Test
    void query_bounds_window_by_epoch_millis_range() {
        String body = IndexerAlertSearchSource.searchBody(1700000000000L, 1700000030000L, "vuln-webapp");
        assertTrue(body.contains("\"gte\":1700000000000"), "창 시작(epoch ms)");
        assertTrue(body.contains("\"lte\":1700000030000"), "창 끝(epoch ms)");
        assertTrue(body.contains("\"format\":\"epoch_millis\""), "epoch_millis 포맷");
    }
}
