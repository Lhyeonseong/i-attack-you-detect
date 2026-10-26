package com.capstone.vuln.measure;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * IndexerTls (S4-5 (3-F) 수정): 인덱서와 같은 모양의 서버 — 테스트 CA 가 서명한 인증서, SAN = DNS:wazuh.indexer 만,
 * 접속은 127.0.0.1 — 에서 확인한다. 같은 JVM 에서 호스트명 검증이 켜진 java.net.http 클라이언트를 먼저 써도
 * (BenignRunIT 실패 순서) 인덱서 클라이언트는 CA 체인 검증 모드·trust-all 모드 모두 연결되고, 다른 CA 면 거부된다.
 * trust-all 모드 = CA 를 주지 않은 기존 ATTACK 경로(MeasureConfig 기본값) 동작.
 */
class IndexerTlsTest {

    @TempDir
    static Path dir;
    private static HttpsServer server;
    private static String baseUrl;
    private static Path caPem;
    private static Path otherCaPem;

    private static void keytool(String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) {
            throw new IllegalStateException("keytool 실패: " + String.join(" ", args) + "\n" + out);
        }
    }

    @BeforeAll
    static void startServer() throws Exception {
        String pw = "test-only";
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=test-indexer-ca",
                "-ext", "bc:c", "-validity", "2", "-storetype", "PKCS12", "-keystore", "ca.p12", "-storepass", pw);
        keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", "ca.p12", "-storepass", pw, "-file", "ca.pem");
        keytool("-genkeypair", "-alias", "leaf", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=wazuh.indexer",
                "-validity", "2", "-storetype", "PKCS12", "-keystore", "leaf.p12", "-storepass", pw);
        keytool("-certreq", "-alias", "leaf", "-keystore", "leaf.p12", "-storepass", pw, "-file", "leaf.csr");
        keytool("-gencert", "-rfc", "-alias", "ca", "-keystore", "ca.p12", "-storepass", pw, "-infile", "leaf.csr",
                "-outfile", "leaf.pem", "-ext", "SAN=dns:wazuh.indexer", "-validity", "2");
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", "ca.pem", "-keystore", "leaf.p12", "-storepass", pw);
        keytool("-importcert", "-alias", "leaf", "-file", "leaf.pem", "-keystore", "leaf.p12", "-storepass", pw);
        keytool("-genkeypair", "-alias", "other", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=other-ca",
                "-ext", "bc:c", "-validity", "2", "-storetype", "PKCS12", "-keystore", "other.p12", "-storepass", pw);
        keytool("-exportcert", "-rfc", "-alias", "other", "-keystore", "other.p12", "-storepass", pw, "-file", "other.pem");
        caPem = dir.resolve("ca.pem");
        otherCaPem = dir.resolve("other.pem");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(dir.resolve("leaf.p12").toFile())) {
            ks.load(in, pw.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw.toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverCtx));
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = "{\"hits\":{\"hits\":[]}}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        baseUrl = "https://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    private static String search(Path ca) {
        return new IndexerAlertSearchSource(baseUrl, "wazuh-alerts-*", "u", "p", "vuln-webapp", ca)
                .search(Instant.EPOCH, Instant.EPOCH.plusSeconds(1));
    }

    /**
     * BenignRunIT 실패 순서 재현: 호스트명 검증이 켜진(JDK 기본) java.net.http 클라이언트를 먼저 쓰고(같은 CA 를 신뢰해도
     * 127.0.0.1 은 SAN 불일치로 실패) 그다음 인덱서 클라이언트 — CA 모드·trust-all 모드 둘 다 연결된다.
     */
    @Test
    void indexerClientConnectsAfterHostnameVerifyingClientWasUsedFirst() throws Exception {
        assumeFalse(Boolean.getBoolean("jdk.internal.httpclient.disableHostnameVerification"),
                "JVM 전역 속성이 켜져 있으면 재현 조건이 아니다");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        try (InputStream in = new FileInputStream(caPem.toFile())) {
            trust.setCertificateEntry("ca", java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in));
        }
        tmf.init(trust);
        SSLContext verifying = SSLContext.getInstance("TLS");
        verifying.init(null, tmf.getTrustManagers(), null);
        HttpClient first = HttpClient.newBuilder().sslContext(verifying).build();
        Exception e = assertThrows(Exception.class, () -> first.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/")).build(), HttpResponse.BodyHandlers.ofString()));
        assertSanMismatch(e);

        // 수정 전 구현(확장형 아닌 X509TrustManager trust-all + 전역 속성 의존)은 이 순서에서 원래 오류로 실패한다
        SSLContext legacy = SSLContext.getInstance("TLS");
        legacy.init(null, new javax.net.ssl.TrustManager[] {new javax.net.ssl.X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
            }

            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[0];
            }
        }}, null);
        Exception legacyError = assertThrows(Exception.class, () -> HttpClient.newBuilder().sslContext(legacy).build().send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/")).build(), HttpResponse.BodyHandlers.ofString()));
        assertSanMismatch(legacyError);

        assertEquals("{\"hits\":{\"hits\":[]}}", search(caPem), "CA 모드: 체인 검증 통과, 호스트명만 생략");
        assertEquals("{\"hits\":{\"hits\":[]}}", search(null), "trust-all 모드(기존 ATTACK 경로)");
    }

    /** 원인 체인에 S4-5 (3-F) 와 같은 "No subject alternative names matching IP address 127.0.0.1" */
    private static void assertSanMismatch(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (String.valueOf(t.getMessage()).contains("No subject alternative names matching IP address 127.0.0.1")) {
                return;
            }
        }
        throw new AssertionError("SAN 불일치 오류가 아니다", e);
    }

    /** CA 모드는 체인을 실제로 검증한다 — 다른 CA 로는 연결되지 않는다 */
    @Test
    void chainIsVerifiedAgainstTheGivenCa() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> search(otherCaPem));
        assertEquals("인덱서 alert 질의 I/O 실패", e.getMessage());
    }

    /** 두 모드 모두 확장형 — JDK 의 호스트명 검증 래퍼(AbstractTrustManagerWrapper)가 붙지 않는다 */
    @Test
    void bothModesAreExtendedTrustManagers() {
        assertInstanceOf(X509ExtendedTrustManager.class, IndexerTls.trustAll());
        assertInstanceOf(X509ExtendedTrustManager.class, IndexerTls.chainOnly(caPem));
        assertThrows(IllegalStateException.class, () -> IndexerTls.chainOnly(dir.resolve("missing.pem")));
    }
}
