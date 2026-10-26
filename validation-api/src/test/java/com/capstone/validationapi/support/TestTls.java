package com.capstone.validationapi.support;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 테스트 전용 throwaway 자체서명 인증서(운영 인증서와 무관). SSL 번들이 기동 시 유효한 PEM 을 읽도록 임시파일로 쓴다.
 * MockMvc(MOCK 환경)는 커넥터를 안 띄우지만 SslBundles 빈이 PEM 을 읽으므로 유효한 파일이 필요하다.
 */
public final class TestTls {

    private static final String CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDJTCCAg2gAwIBAgIUVuSBxrSupG6MVXIlzE0Jny3syG0wDQYJKoZIhvcNAQEL
            BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAyMjA4MDkyNloXDTM2MTAx
            OTA4MDkyNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEAn3vIBvmN0wNUGq/sJjlRILTPNwqMnd/2ie9DvwevFXPy
            pdpqcrWRRfXyt1rl9T/kn2P9Fw8MPBYN+HhZlXebW2XEH1w17Z3NNYG2ff9TSUj1
            JifCl5eoPY8GF6xXM9joYvmiZEP6r4VncIbNIupxaxSPgT0G6moPNGjHV+4uN+mk
            3tHtdxmblJxMPS9Su6P9kANjUHLFwzd396EgCXy13q5216V/W66Asdv6WgjPmWdF
            BbEhBLRlRmYhi0PcxeZuyAo65YB7Ue3aKcQUF8t/qksdAWViOZ0w7xFuHSNHNRdY
            ratixrgeJph6iFqFUqI8o0qmFPrPMWZNEMMOTLIjbwIDAQABo28wbTAdBgNVHQ4E
            FgQUz9rgt4CzOL4FrPhMToZa7pRGeSIwHwYDVR0jBBgwFoAUz9rgt4CzOL4FrPhM
            ToZa7pRGeSIwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
            BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAI9fzfP8YcpbpjRYKz+WtwaE8k6NWYpB
            TQQWgAdOx7U1zZzqlspogrA0WlnVED9Ii7Y/GvN4Hnn0uFQl9UAw/KXO2FfbySmh
            99UuC6xZs+/2/DDOl3bQcozTQv+1EzeZVrsrbhdv07QhXDthdz/wu9hkwhqCf2wa
            ErSPlcMy0deXw7nPIUBJLyRCJ46e0ncTCdOdCaGehQ+THXVn+MvZ+OVbbtxS4aK2
            aqBOpAvBVb3V8QcRrobg1aU0If6KtjUvHZba0Ih+SYOWcI/Y3eDkVYTJG8gVUcg2
            kt0D5bwGd8FT8rz5WpyqiiW1asSjaqygruFXIFKEscGDKXqy91++1ZY=
            -----END CERTIFICATE-----
            """;

    private static final String KEY = """
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfe8gG+Y3TA1Qa
            r+wmOVEgtM83Coyd3/aJ70O/B68Vc/Kl2mpytZFF9fK3WuX1P+SfY/0XDww8Fg34
            eFmVd5tbZcQfXDXtnc01gbZ9/1NJSPUmJ8KXl6g9jwYXrFcz2Ohi+aJkQ/qvhWdw
            hs0i6nFrFI+BPQbqag80aMdX7i436aTe0e13GZuUnEw9L1K7o/2QA2NQcsXDN3f3
            oSAJfLXernbXpX9broCx2/paCM+ZZ0UFsSEEtGVGZiGLQ9zF5m7ICjrlgHtR7dop
            xBQXy3+qSx0BZWI5nTDvEW4dI0c1F1itq2LGuB4mmHqIWoVSojyjSqYU+s8xZk0Q
            ww5MsiNvAgMBAAECggEABlhMWvVZY8hsHiuwP3e5oeLPo6bzH+Il0tMGukuPTFEy
            mXqZEDs9A7Ax7y2EnJSQKe82cHu+xt0xwm2MqC+mqfo11Ubmi6+NgdAeoeCjQEp7
            cQB/82arNi0XLEtE+jZqTcBqFNxyKsLUnLDK6dVd8clS9EH99nGFwqtbKEUSPah+
            j/nfF47EhHYXpgDC+lrVLQ1cYD7IrEKz0lpUwTxlCEOjpZ/jX+sxNVtsWpGO4g1+
            NDTn0xJyDgRAljCqfPKG3GJd2F7Wh+cAhCEfmVPTIA394200zbVzCfnWWcilRb7r
            E61Kr8uC7+fiLaaznuaKJ4mPaWvhtawOuVGFT351cQKBgQDQs8im3j84/lAQWuNJ
            lG57+Opv9n/ISkCGRdEu3124e0jH3NlU3IB7I7tF6TEMQ+NgAT64+pYqkqOi1fBc
            OfcWlgU1SEVNtCPGJKvmyRSrnnzLecq8Mw+J5J+p3TqrU/iqSRBf04AXr98R+Woa
            Zg4qqh+FXFELJayIDWQQ3P5U/QKBgQDDoHzl19X9/ai2ijfHZAlehFMASPKSnE6V
            CR259jtv305CQ28vbMvbem3Gge+DGBSHLrAxtoD1NSMMo8qydl2XiH935OeAehiV
            tXgpqcFShQ1sjgrRdtoIPAouuA3hfI9hwCSQr/nFEIgciy/qmmo0l5naMaFoQRhy
            NOXEt4fb2wKBgQDNmpBudDzstP3DXwbTkjtWPt8W9kzk0OHIZjeyabM2752/6D7j
            b2fT6FuygA0l/CughRl5usT9pAE5hnKJKUHXKmxvFYfRCUrFBZOkhSyr9jMTciTc
            S6FfQ7BX8+68orkzaU+MWBy1OToVxxVUdH44YekzxMLCrJbQYgDW7CBTMQKBgAfq
            iqNSZJpulVEtrqwm5Coq+KDeUtKT+KoXQFiyGh2gz63mxK0KngU3oxGRWHvZkZsW
            zJJ2bCmACPcN+bnXCFqFb4MOhD+ysSP9v+sPr38DW1O1O8LWKGSE6XSShh1FyReP
            ius/87+Bt8BP8ZRwwzN1nwgxUfLCD5cvhMy9EIZZAoGBAJr6Y/uVRIvBdE+npbmt
            uj6fwXK8t/XEqOovcRgL8nwPgpRBZvFzsob8KYLch4DP1x2zP+zBkeG8tEtV5TBN
            kGFSG67czORxYPEWXsMy8pTu7ySeOuKPapEE74f+Ca+d48CCCTRJA+j0NjGMhXqc
            Twk4gaZP+d8SFdnl3Su+dNSh
            -----END PRIVATE KEY-----
            """;

    private TestTls() {
    }

    /** cert·key 를 임시파일로 쓰고 [certPath, keyPath] 반환. */
    public static String[] writeTempCertAndKey() {
        try {
            Path dir = Files.createTempDirectory("s46-test-tls");
            Path cert = dir.resolve("cert.pem");
            Path key = dir.resolve("key.pem");
            Files.writeString(cert, CERT);
            Files.writeString(key, KEY);
            cert.toFile().deleteOnExit();
            key.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            return new String[]{cert.toAbsolutePath().toString(), key.toAbsolutePath().toString()};
        } catch (Exception e) {
            throw new IllegalStateException("테스트 인증서 쓰기 실패", e);
        }
    }
}
