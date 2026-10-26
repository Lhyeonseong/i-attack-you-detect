package com.capstone.vuln.logging;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S5 Gap #7 — SQLi 앱 룰 100211(요청 신호 확장)의 pcre2 를 vuln_rules.xml 에서 그대로 꺼내 양성·음성에 적용한다.
 * 저장소 룰 파일의 정규식 회귀(AttackLoggerDecoderRegexTest 와 같은 방식) — 운영 확정은 B3 wazuh-logtest(임시 manager).
 * B안: args 는 http_request.args(디코딩값, keyword=<값>). 룰은 응답·정답지 미사용.
 */
class SqliRuleRegexTest {

    private static final Path RULES = Path.of("docker/config/wazuh_manager/rules/vuln_rules.xml");

    /** rule id 의 http_request.args pcre2 원문 → Java Pattern (XML 엔티티 복원) */
    private static Pattern argsPattern(String ruleId) throws IOException {
        String xml = Files.readString(RULES);
        Matcher rule = Pattern.compile("<rule id=\"" + ruleId + "\".*?</rule>", Pattern.DOTALL).matcher(xml);
        assertTrue(rule.find(), "rule 없음: " + ruleId);
        Matcher f = Pattern.compile("<field name=\"http_request\\.args\"[^>]*>(.*?)</field>", Pattern.DOTALL)
                .matcher(rule.group());
        assertTrue(f.find(), ruleId + " 에 http_request.args 필드 없음");
        String re = f.group(1).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
        return Pattern.compile(re);
    }

    private static boolean fires(Pattern p, String keyword) {
        // Wazuh 는 http_request.args 전체("keyword=<값>")에 pcre2 를 match 한다
        return p.matcher("keyword=" + keyword).find();
    }

    // Caldera error-based probe(') 외 다양한 주입 — 단일 페이로드 아님
    private static final List<String> POSITIVE = List.of(
            "'", "\"", "')", "' OR '1'='1", "' OR 1=1--", "1;--", "admin'#", "' UNION SELECT NULL--", "'/*",
            "' AND SLEEP(1)--");

    // 정상 검색어 — 따옴표·SQL 토큰 없음 + 하이픈/점 포함 회귀 샘플(홀드아웃 코퍼스 아님)
    private static final List<String> NEGATIVE = List.of(
            "laptop--pro", "report.pdf", "galaxy s24", "노트북 15인치", "wireless mouse", "27 monitor", "keyboard");

    // 기록만 — 따옴표 포함 정상어. 발동해도 가드레일이 측정(룰로 회피 안 함)
    private static final List<String> RECORD_ONLY = List.of("O'Reilly", "it's");

    @Test
    void rule100211FiresOnAllInjectionSignals() throws IOException {
        Pattern p = argsPattern("100211");
        for (String k : POSITIVE) {
            assertTrue(fires(p, k), "100211 발동해야 함: " + k);
        }
    }

    @Test
    void rule100211DoesNotFireOnNormalTerms() throws IOException {
        Pattern p = argsPattern("100211");
        for (String k : NEGATIVE) {
            assertFalse(fires(p, k), "100211 발동 금지(정상): " + k);
        }
    }

    /** 100210(기존 좁은 룰)은 단일 작은따옴표 probe 를 못 잡는다 = Gap #7. 100211 이 메운다(Before/After 단위 근거) */
    @Test
    void rule100210MissesLoneQuoteButRule100211Catches() throws IOException {
        Pattern narrow = argsPattern("100210");
        Pattern broad = argsPattern("100211");
        assertFalse(fires(narrow, "'"), "100210 은 단일 작은따옴표를 못 잡는다(Gap #7)");
        assertTrue(fires(broad, "'"), "100211 은 단일 작은따옴표를 잡는다");
        // UNION 계열은 둘 다 잡는다(기존 경로 유지)
        assertTrue(fires(narrow, "' UNION SELECT NULL--"));
        assertTrue(fires(broad, "' UNION SELECT NULL--"));
    }

    /** 기록만 — 따옴표 포함 정상어는 100211 이 발동한다(가드레일1이 측정, 실패 아님). 값만 고정 확인 */
    @Test
    void quotedNormalWordsFireAndAreMeasuredByGuardrail() throws IOException {
        Pattern p = argsPattern("100211");
        for (String k : RECORD_ONLY) {
            assertTrue(fires(p, k), "따옴표 포함 정상어는 발동(기록만, 가드레일 측정): " + k);
        }
    }
}
