package com.capstone.vuln.measure;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * 정상 코퍼스 manifest (ADR-S4-01 v1.8 R17·R18, detections/corpus/benign/*.yaml). 정상 라벨은 이 파일에만 있다(B안).
 *
 * <p>읽을 때 items_sha256(각 항목 'seq TAB endpoint TAB param TAB value LF' 를 이어 붙인 sha256)을 다시 계산해
 * 다르면 실패한다 — 측정에 쓴 코퍼스가 고정한 그 코퍼스임을 보장. seq 는 1부터 빈틈없이 증가해야 한다.
 */
public record BenignCorpus(String name, String itemsSha256, List<Item> items) {

    /** 요청 1건 — endpoint 의 param 하나에 value 를 실어 GET */
    public record Item(int seq, String endpoint, String param, String value) {

        /** 보낼 요청 대상: path + "?" + param + "=" + 1회 URL 인코딩 값 (eve http.url 과 같은 원문 형태) */
        public String requestTarget() {
            return endpoint + "?" + param + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
        }

        /** 앱 로그 http_request.args 형태 — 컨트롤러가 디코딩된 값으로 "param=value" 를 기록한다 */
        public String appArgs() {
            return param + "=" + value;
        }
    }

    public static BenignCorpus load(Path file) {
        String text;
        try {
            text = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        Map<String, Object> root = new Yaml(new SafeConstructor(new LoaderOptions())).load(text);
        String name = String.valueOf(root.get("corpus"));
        if (!"BENIGN".equals(root.get("label"))) {
            throw new IllegalStateException("코퍼스 label 이 BENIGN 이 아니다: " + file);
        }
        String declared = String.valueOf(root.get("items_sha256"));
        List<Item> items = new ArrayList<>();
        StringBuilder canonical = new StringBuilder();
        for (Object o : (List<?>) root.get("items")) {
            Map<?, ?> m = (Map<?, ?>) o;
            Item it = new Item(((Number) m.get("seq")).intValue(), String.valueOf(m.get("endpoint")),
                    String.valueOf(m.get("param")), String.valueOf(m.get("value")));
            if (it.seq() != items.size() + 1) {
                throw new IllegalStateException("seq 가 1부터 연속이 아니다: " + it.seq() + " (" + file + ")");
            }
            items.add(it);
            canonical.append(it.seq()).append('\t').append(it.endpoint()).append('\t').append(it.param())
                    .append('\t').append(it.value()).append('\n');
        }
        String actual = sha256(canonical.toString().getBytes(StandardCharsets.UTF_8));
        if (!actual.equals(declared)) {
            throw new IllegalStateException("items_sha256 불일치 — 선언 " + declared + ", 계산 " + actual + " (" + file + ")");
        }
        return new BenignCorpus(name, declared, List.copyOf(items));
    }

    /** 파일 전체 sha256 (증거 로그·ADR 기록용) */
    public static String fileSha256(Path file) {
        try {
            return sha256(Files.readAllBytes(file));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
