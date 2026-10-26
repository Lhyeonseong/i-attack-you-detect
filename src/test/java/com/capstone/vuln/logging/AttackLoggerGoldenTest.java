package com.capstone.vuln.logging;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.auth.BruteForceInput;
import com.capstone.vuln.auth.BruteForceValidator;
import com.capstone.vuln.correlation.CorrelationInfo;
import com.capstone.vuln.correlation.CorrelationSource;
import com.capstone.vuln.evaluator.SqliEvaluator;
import com.capstone.vuln.evaluator.SqliResultType;
import com.capstone.vuln.file.PathTraversalInput;
import com.capstone.vuln.file.PathTraversalValidator;
import com.capstone.vuln.product.SqliInput;
import com.capstone.vuln.product.SqliValidator;
import com.capstone.vuln.ssrf.SsrfInput;
import com.capstone.vuln.ssrf.SsrfValidator;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * OCSF HTTP Activity 로그 바이트 단위 골든 (S3 Boot 4.1 업그레이드 전 기준선, 3.5.13).
 *
 * <p>기대값은 S4-STACK-2-SMOKE(2026-10-20T20:06:58Z~20:10:51Z) 의 실제 attack.json.log 줄을 그대로 옮긴 것이고,
 * 미태깅 1줄은 같은 날 슬라이스 2 Gap 시험 curl 요청(19:42:34Z) 줄이다. 입력도 그 줄의 값(time·rid·args·UA·latency·body_length)을
 * 그대로 넣어, 직렬화 결과가 실제 로그와 한 바이트도 다르지 않은지 본다 — 키 순서(하위 객체 포함)·필드 집합·
 * time(epoch ms 정수)·null 리터럴·evidence 배열·한 줄 형식이 전부 이 비교에 들어간다.
 */
class AttackLoggerGoldenTest {

    private static final String SRC_IP = "172.20.0.1";
    private static final String UPLOAD_DIR = "/opt/target/uploads";

    private final SqliValidator sqliValidator = new SqliValidator(new SqliEvaluator());
    private final PathTraversalValidator pathTraversalValidator = new PathTraversalValidator();
    private final BruteForceValidator bruteForceValidator = new BruteForceValidator();
    private final SsrfValidator ssrfValidator = new SsrfValidator();

    private static CorrelationInfo caldera(String technique, String ability, String userAgent) {
        return new CorrelationInfo("qpiere", technique, ability, CorrelationSource.HEADER, SRC_IP, userAgent);
    }

    private static <C> ValidationContext<C> ctx(String rid, CorrelationInfo correlation, long time,
                                                int statusCode, C input) {
        return new ValidationContext<>(rid, correlation, Instant.ofEpochMilli(time), statusCode, input);
    }

    private static PathTraversalInput passwdReturned() {
        return PathTraversalInput.fileReturned(Path.of(UPLOAD_DIR + "/../../../../etc/passwd"), Path.of(UPLOAD_DIR),
                888, "text");
    }

    private static void assertGolden(String expected, String rid, HttpExchange exchange,
                                     CorrelationInfo correlation, AttackObservation observation) throws Exception {
        String actual = AttackLogger.toHttpActivityJson(rid, exchange, correlation, observation);
        assertArrayEquals(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8),
                () -> "OCSF 로그 바이트가 골든과 다름\nexpected=" + expected + "\nactual  =" + actual);
    }

    @Test
    void sqliSucceeded() throws Exception {
        String ua = "Caldera/qpiere/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c";
        String rid = "27b4875a-ad00-4cf1-bee1-e11a936f01d8";
        long time = 1792526840652L;
        CorrelationInfo correlation = caldera("T1190", "e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c", ua);
        AttackObservation observation = sqliValidator.observe(
                ctx(rid, correlation, time, 200, SqliInput.ofError(
                        "StatementCallback; bad SQL grammar [SELECT * FROM products WHERE name LIKE '%'%'] | ", 132)),
                SqliResultType.SQL_ERROR_EXPOSED);

        assertGolden("""
                {"time":1792526840652,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":3,"rid":"27b4875a-ad00-4cf1-bee1-e11a936f01d8","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/products/search"},"user_agent":"Caldera/qpiere/T1190/e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c","args":"keyword='"},"http_response":{"code":200,"latency_ms":132,"body_length":141},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"RESPONSE_PATTERN"}],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":"qpiere","ability_id":"e3f1a9c7-2b4d-4e6f-a8c2-5d7e9f1b3a5c","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "GET", "/api/products/search", ua, "keyword='",
                        200, 132, 141),
                correlation, observation);
    }

    @Test
    void pathTraversalSucceeded() throws Exception {
        String ua = "Caldera/qpiere/T1190/c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b";
        String rid = "0dc15bb5-60d4-4aea-994d-a9756f00e750";
        long time = 1792526965034L;
        CorrelationInfo correlation = caldera("T1190", "c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b", ua);
        AttackObservation observation = pathTraversalValidator.validate(
                ctx(rid, correlation, time, 200, passwdReturned()));

        assertGolden("""
                {"time":1792526965034,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":3,"rid":"0dc15bb5-60d4-4aea-994d-a9756f00e750","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/files/download"},"user_agent":"Caldera/qpiere/T1190/c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b","args":"filename=../../../../etc/passwd"},"http_response":{"code":200,"latency_ms":45,"body_length":888},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"FILE_DISCLOSED"}],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":"qpiere","ability_id":"c4e8f2b1-9d5a-4f7e-b3c6-8a2d1e9f0c4b","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "GET", "/api/files/download", ua,
                        "filename=../../../../etc/passwd", 200, 45, 888),
                correlation, observation);
    }

    @Test
    void bruteForceFailed() throws Exception {
        String ua = "Caldera/qpiere/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";
        String rid = "911092ef-944b-4754-8ac6-de9b73685d68";
        long time = 1792527010170L;
        CorrelationInfo correlation = caldera("T1110", "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d", ua);
        AttackObservation observation = bruteForceValidator.validate(
                ctx(rid, correlation, time, 401, new BruteForceInput(BruteForceInput.ResultType.AUTH_FAIL)));

        assertGolden("""
                {"time":1792527010170,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":6,"rid":"911092ef-944b-4754-8ac6-de9b73685d68","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"POST","url":{"path":"/api/auth/login"},"user_agent":"Caldera/qpiere/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","args":"username=user1"},"http_response":{"code":401,"latency_ms":61,"body_length":60},"validation":{"outcome":"FAILED","evidence":[],"validator_version":"v1","technique_id":"T1110"},"correlation":{"op_id":"qpiere","ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "POST", "/api/auth/login", ua, "username=user1",
                        401, 61, 60),
                correlation, observation);
    }

    @Test
    void bruteForceSucceeded() throws Exception {
        String ua = "Caldera/qpiere/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d";
        String rid = "1f5e8ab3-42eb-4c36-a48a-211354bc53b9";
        long time = 1792527010444L;
        CorrelationInfo correlation = caldera("T1110", "7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d", ua);
        AttackObservation observation = bruteForceValidator.validate(
                ctx(rid, correlation, time, 200, new BruteForceInput(BruteForceInput.ResultType.AUTH_SUCCESS)));

        assertGolden("""
                {"time":1792527010444,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":6,"rid":"1f5e8ab3-42eb-4c36-a48a-211354bc53b9","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"POST","url":{"path":"/api/auth/login"},"user_agent":"Caldera/qpiere/T1110/7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","args":"username=user1"},"http_response":{"code":200,"latency_ms":143,"body_length":266},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"CREDENTIAL_VALID"}],"validator_version":"v1","technique_id":"T1110"},"correlation":{"op_id":"qpiere","ability_id":"7aa89a87-3fd7-4d52-8c9e-1e5b2f4c6a3d","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "POST", "/api/auth/login", ua, "username=user1",
                        200, 143, 266),
                correlation, observation);
    }

    @Test
    void ssrfSucceeded() throws Exception {
        String ua = "Caldera/qpiere/T1190/a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
        String rid = "94d3926b-7a44-4536-98d3-a44fea7757ca";
        long time = 1792526908406L;
        CorrelationInfo correlation = caldera("T1190", "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60", ua);
        AttackObservation observation = ssrfValidator.validate(
                ctx(rid, correlation, time, 200, SsrfInput.fetched(true, true, "169.254.169.254", 200, 40)));

        assertGolden("""
                {"time":1792526908406,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":3,"rid":"94d3926b-7a44-4536-98d3-a44fea7757ca","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/preview"},"user_agent":"Caldera/qpiere/T1190/a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60","args":"url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role"},"http_response":{"code":200,"latency_ms":347,"body_length":40},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"METADATA_REACHED"}],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":"qpiere","ability_id":"a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "GET", "/api/preview", ua,
                        "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/mock-iam-role",
                        200, 347, 40),
                correlation, observation);
    }

    @Test
    void ssrfControlFailed() throws Exception {
        String ua = "Caldera/qpiere/T1190/a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60";
        String rid = "9deaf756-9b66-4577-9224-ce0578c9f095";
        long time = 1792526908942L;
        CorrelationInfo correlation = caldera("T1190", "a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60", ua);
        AttackObservation observation = ssrfValidator.validate(
                ctx(rid, correlation, time, 200, SsrfInput.fetched(false, false, "example.com", 200, 577)));

        assertGolden("""
                {"time":1792526908942,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":3,"rid":"9deaf756-9b66-4577-9224-ce0578c9f095","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/preview"},"user_agent":"Caldera/qpiere/T1190/a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60","args":"url=http://example.com/"},"http_response":{"code":200,"latency_ms":82,"body_length":577},"validation":{"outcome":"FAILED","evidence":[],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":"qpiere","ability_id":"a7f3c1d9-5e2b-4a6c-9f08-1b2c3d4e5f60","source":"HEADER"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "GET", "/api/preview", ua, "url=http://example.com/",
                        200, 82, 577),
                correlation, observation);
    }

    @Test
    void untaggedRequestWritesNullCorrelationIds() throws Exception {
        String ua = "curl/8.5.0";
        String rid = "5d23de03-41c7-4d06-abd5-b060cdb2c72a";
        long time = 1792525354463L;
        // Caldera 헤더·UA 가 없는 수동 요청: extractor 는 opId·techniqueId·abilityId=null, source=NONE 을 준다
        CorrelationInfo correlation = new CorrelationInfo(null, null, null, CorrelationSource.NONE, SRC_IP, ua);
        AttackObservation observation = pathTraversalValidator.validate(
                ctx(rid, correlation, time, 200, passwdReturned()));

        assertGolden("""
                {"time":1792525354463,"metadata":{"version":"1.9.0","log_name":"attack_http_activity"},"class_uid":4002,"class_name":"HTTP Activity","activity_id":3,"rid":"5d23de03-41c7-4d06-abd5-b060cdb2c72a","src_endpoint":{"ip":"172.20.0.1"},"http_request":{"http_method":"GET","url":{"path":"/api/files/download"},"user_agent":"curl/8.5.0","args":"filename=../../../../etc/passwd"},"http_response":{"code":200,"latency_ms":158,"body_length":888},"validation":{"outcome":"SUCCEEDED","evidence":[{"kind":"FILE_DISCLOSED"}],"validator_version":"v1","technique_id":"T1190"},"correlation":{"op_id":null,"ability_id":null,"source":"NONE"}}""",
                rid, new HttpExchange(Instant.ofEpochMilli(time), "GET", "/api/files/download", ua,
                        "filename=../../../../etc/passwd", 200, 158, 888),
                correlation, observation);
    }
}
