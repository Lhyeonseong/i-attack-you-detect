package com.capstone.vuln.logging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * G4 — application.log 의 ATTACK_REQUEST / ATTACK_RESPONSE 텍스트 줄이 Wazuh decoder 정규식에 맞는지.
 *
 * <p>decoder 는 저장소 파일(docker/config/wazuh_manager/decoders/vuln_decoder.xml)에서 그대로 읽고, Wazuh OS_Regex 문법을
 * Java 정규식으로 옮겨 AttackLogger 가 실제로 남긴 메시지에 적용한다. prematch 이후 본문만 보므로 Boot 기본 로그
 * 접두 패턴(시각·스레드·로거명)과는 무관하다. result_type 은 Wazuh 룰 16개가 쓰는 필드다.
 */
class AttackLoggerDecoderRegexTest {

    private static final Path DECODER = Path.of("docker/config/wazuh_manager/decoders/vuln_decoder.xml");

    private final AttackLogger attackLogger = new AttackLogger();
    private final Logger logger = (Logger) LoggerFactory.getLogger(AttackLogger.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private static final CorrelationInfo CALDERA = new CorrelationInfo("qpiere", "T1190",
            "e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c", CorrelationSource.HEADER, "172.20.0.1",
            "Caldera/qpiere/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c");
    private static final CorrelationInfo BF = new CorrelationInfo("qpiere", "T1110",
            "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d", CorrelationSource.HEADER, "172.20.0.1",
            "Caldera/qpiere/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d");
    private static final CorrelationInfo UNTAGGED = new CorrelationInfo(null, null, null,
            CorrelationSource.NONE, "172.20.0.1", "curl/8.5.0");

    @BeforeEach
    void attach() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    private String lastMessage() {
        List<ILoggingEvent> events = appender.list;
        return events.get(events.size() - 1).getFormattedMessage();
    }

    /** vuln_decoder.xml 에서 decoder 이름의 prematch 또는 regex 원문 */
    private static String decoderPattern(String decoderName, String tag) throws IOException {
        String xml = Files.readString(DECODER);
        Matcher m = Pattern.compile("<decoder name=\"" + Pattern.quote(decoderName) + "\">(.*?)</decoder>",
                Pattern.DOTALL).matcher(xml);
        assertTrue(m.find(), "decoder 없음: " + decoderName);
        Matcher t = Pattern.compile("<" + tag + ">(.*?)</" + tag + ">", Pattern.DOTALL).matcher(m.group(1));
        assertTrue(t.find(), decoderName + " 에 <" + tag + "> 없음");
        return t.group(1);
    }

    /**
     * Wazuh OS_Regex → Java. 이 decoder 들이 쓰는 표현만 옮기고, 그 밖의 이스케이프가 생기면 실패시킨다
     * (decoder 가 바뀌었는데 테스트가 조용히 통과하지 않도록).
     * OS_Regex: \w = A-Z a-z 0-9 '-' '@' '_', \d = 0-9, \S = 공백 아님, \s = 공백, \| = '|' 문자. 앵커 없는 부분 일치.
     */
    private static Pattern osRegex(String os) {
        StringBuilder java = new StringBuilder();
        for (int i = 0; i < os.length(); i++) {
            char c = os.charAt(i);
            if (c == '\\') {
                char e = os.charAt(++i);
                switch (e) {
                    case 'w' -> java.append("[A-Za-z0-9_@-]");
                    case 'd' -> java.append("[0-9]");
                    case 'S' -> java.append("\\S");
                    case 's' -> java.append("\\s");
                    case '|' -> java.append("\\|");
                    default -> throw new IllegalArgumentException("옮기지 않은 OS_Regex 이스케이프 \\" + e + " in " + os);
                }
            } else if (c == '(' || c == ')' || c == '+' || c == '*') {
                java.append(c);
            } else {
                java.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(java.toString());
    }

    private static Matcher decode(String message, String parent, String child) throws IOException {
        assertTrue(osRegex(decoderPattern(parent, "prematch")).matcher(message).find(),
                "prematch 불일치 (" + parent + "): " + message);
        Matcher m = osRegex(decoderPattern(child, "regex")).matcher(message);
        assertTrue(m.find(), "regex 불일치 (" + child + "): " + message);
        return m;
    }

    @Test
    void attackRequestFromCalderaYieldsRidEndpointOpIdAndIp() throws IOException {
        attackLogger.logRequest("27b4875a-ad00-4cf1-bee1-e11a936f01d8", "/api/products/search", "GET",
                CALDERA, null, "keyword='");

        Matcher m = decode(lastMessage(), "vuln-attack-request", "vuln-attack-request-fields");
        assertEquals("27b4875a-ad00-4cf1-bee1-e11a936f01d8", m.group(1));
        assertEquals("/api/products/search", m.group(2));
        assertEquals("qpiere", m.group(3));
        assertEquals("172.20.0.1", m.group(4));
    }

    @Test
    void attackRequestWithoutCalderaTagStillDecodes() throws IOException {
        attackLogger.logRequest("5d23de03-41c7-4d06-abd5-b060cdb2c72a", "/api/files/download", "GET",
                UNTAGGED, null, "filename=../../../../etc/passwd");

        Matcher m = decode(lastMessage(), "vuln-attack-request", "vuln-attack-request-fields");
        assertEquals("/api/files/download", m.group(2));
        assertEquals("null", m.group(3)); // opId 없음 → slf4j 가 'null' 로 쓴다
        assertEquals("172.20.0.1", m.group(4));
    }

    @Test
    void loginRequestYieldsUsername() throws IOException {
        attackLogger.logRequest("911092ef-944b-4754-8ac6-de9b73685d68", "/api/auth/login", "POST",
                BF, "user1", "login_attempt");

        Matcher m = decode(lastMessage(), "vuln-attack-request", "vuln-attack-request-user");
        assertEquals("user1", m.group(1));
    }

    @Test
    void attackResponseYieldsStatusAndResultTypeForEveryScenario() throws IOException {
        record Case(String endpoint, CorrelationInfo correlation, int status, String resultType, String detail) {
        }
        List<Case> cases = List.of(
                new Case("/api/products/search", CALDERA, 200, "SQL_ERROR_EXPOSED",
                        "error=StatementCallback; bad SQL grammar [SELECT * FROM products WHERE name LIKE '%'%'] | "),
                new Case("/api/products/search", CALDERA, 200, "UNION_DATA_LEAKED", "rows=4 elapsed=3"),
                new Case("/api/files/download", CALDERA, 200, "FILE_RETURNED", "type=text size=888"),
                new Case("/api/files/download", UNTAGGED, 404, "NOT_FOUND", "path=/opt/target/uploads/x"),
                new Case("/api/auth/login", BF, 401, "AUTH_FAIL", "invalid_credentials"),
                new Case("/api/auth/login", BF, 200, "AUTH_SUCCESS", "token_issued user=user1"),
                new Case("/api/preview", CALDERA, 200, "FETCHED",
                        "fetched host=169.254.169.254 code=200 internal=true sentinel=true"),
                new Case("/api/preview", CALDERA, 400, "BLOCKED", "scheme guard blocked non-http(s) url (host=null)"));

        for (Case c : cases) {
            attackLogger.logResponse("rid-" + c.resultType(), c.endpoint(), c.correlation(), c.status(),
                    c.resultType(), c.detail());

            Matcher m = decode(lastMessage(), "vuln-attack-response", "vuln-attack-response-fields");
            assertEquals("rid-" + c.resultType(), m.group(1), c.resultType());
            assertEquals(c.endpoint(), m.group(2), c.resultType());
            assertEquals(String.valueOf(c.correlation().getOpId()), m.group(3), c.resultType());
            assertEquals(String.valueOf(c.status()), m.group(4), c.resultType());
            assertEquals(c.resultType(), m.group(5), c.resultType());
        }
    }
}
