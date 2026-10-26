package com.capstone.vuln.measure;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 인덱서(랩, 127.0.0.1:9200) TLS — 인덱서 인증서 SAN 은 DNS:wazuh.indexer 뿐이라 127.0.0.1 접속은 호스트명 검증을 통과하지 못한다.
 *
 * <p>두 방식 모두 {@link X509ExtendedTrustManager} 를 쓴다. JDK 는 확장형이 아닌 X509TrustManager 만 호스트명 검증 래퍼로 감싸므로,
 * 확장형이면 JVM 전역 속성(jdk.internal.httpclient.disableHostnameVerification — java.net.http 첫 사용 때 한 번만 읽힘)이나
 * 클라이언트 생성 순서와 무관하게 호스트명 검증만 빠진다(S4-5 BenignRunIT 실패 원인 — 2026-10-22 s4-5-benign 로그 (3-F)).
 * <ul>
 *   <li>CA 파일 있음: 그 루트 CA 로 인증서 체인을 검증(PKIX)하고 호스트명 검증만 생략</li>
 *   <li>CA 파일 없음(null): 체인도 검증하지 않음(랩 전용 trust-all — known-gaps Gap #12)</li>
 * </ul>
 */
final class IndexerTls {

    private IndexerTls() {
    }

    static SSLContext context(Path caFile) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {caFile == null ? trustAll() : chainOnly(caFile)}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("인덱서 TLS 컨텍스트 생성 실패", e);
        }
    }

    /** caFile(PEM 루트 CA)로 체인만 검증하는 신뢰 관리자 */
    static X509ExtendedTrustManager chainOnly(Path caFile) {
        X509TrustManager pkix = pkix(caFile);
        return new Extended() {
            @Override
            void check(X509Certificate[] chain, String authType) throws CertificateException {
                pkix.checkServerTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return pkix.getAcceptedIssuers();
            }
        };
    }

    /** 체인·호스트명 모두 검증하지 않는 신뢰 관리자 (CA 파일을 주지 않은 경우 — 기존 동작) */
    static X509ExtendedTrustManager trustAll() {
        return new Extended() {
            @Override
            void check(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }

    private static X509TrustManager pkix(Path caFile) {
        try (InputStream in = Files.newInputStream(caFile)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                ks.setCertificateEntry("indexer-ca-" + i++, c);
            }
            if (i == 0) {
                throw new IllegalStateException("인덱서 CA 파일에 인증서가 없다: " + caFile);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x) {
                    return x;
                }
            }
            throw new IllegalStateException("X509TrustManager 없음");
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("인덱서 CA 파일을 읽지 못했다: " + caFile, e);
        }
    }

    /** 서버 검증 4개 진입점을 check 하나로 모은다. 클라이언트 인증서는 쓰지 않는다 */
    private abstract static class Extended extends X509ExtendedTrustManager {

        abstract void check(X509Certificate[] chain, String authType) throws CertificateException;

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            check(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            check(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("클라이언트 인증서 검증은 쓰지 않는다");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            throw new CertificateException("클라이언트 인증서 검증은 쓰지 않는다");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            throw new CertificateException("클라이언트 인증서 검증은 쓰지 않는다");
        }
    }
}
