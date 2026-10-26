package com.capstone.vuln.measure;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** R17·R18 d — benign-corpus-v1 manifest: 해시 고정, 엔드포인트별 320건(≥ 300), 회귀 세트 문자열 없음, 요청 형태 */
class BenignCorpusTest {

    private static final Path CORPUS = Path.of("detections/corpus/benign/benign-corpus-v1.yaml");

    @Test
    void corpusLoadsWithFixedHashAndPerEndpointCounts() {
        BenignCorpus c = BenignCorpus.load(CORPUS);

        assertEquals("benign-corpus-v1", c.name());
        assertEquals("b73caa5fb6d0bb6e9818b01716480e5fd6009fdedf4da9ea3044854f4e7ca76c", BenignCorpus.fileSha256(CORPUS));
        Map<String, Long> perEndpoint = c.items().stream()
                .collect(Collectors.groupingBy(BenignCorpus.Item::endpoint, Collectors.counting()));
        assertEquals(Map.of("/api/products/search", 320L, "/api/files/download", 320L, "/api/preview", 320L),
                perEndpoint);
        for (int i = 0; i < c.items().size(); i++) {
            assertEquals(i + 1, c.items().get(i).seq());
        }
        Set<String> distinct = new HashSet<>();
        c.items().forEach(it -> assertTrue(distinct.add(it.endpoint() + "|" + it.value()), it.toString()));
        c.items().forEach(it -> assertFalse(it.value().contains("laptop--pro") || it.value().contains("report.pdf"),
                it.toString()));
        c.items().stream().filter(it -> it.endpoint().equals("/api/preview"))
                .forEach(it -> assertTrue(it.value().startsWith("http://") || it.value().startsWith("https://")));
    }

    @Test
    void tamperedItemsAreRejected(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        String text = Files.readString(CORPUS).replace("value: \"xperia go 3\"", "value: \"xperia go 4\"");
        Path tampered = dir.resolve("tampered.yaml");
        Files.writeString(tampered, text);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> BenignCorpus.load(tampered));
        assertTrue(e.getMessage().contains("items_sha256"), e.getMessage());
    }

    /** 요청 대상은 1회 URL 인코딩, 앱 로그 args 는 컨트롤러가 기록하는 디코딩 값(param=value) */
    @Test
    void requestTargetAndAppArgs() {
        BenignCorpus.Item search = new BenignCorpus.Item(1, "/api/products/search", "keyword", "galaxy s24 256gb");
        assertEquals("/api/products/search?keyword=galaxy+s24+256gb", search.requestTarget());
        assertEquals("keyword=galaxy s24 256gb", search.appArgs());

        BenignCorpus.Item preview = new BenignCorpus.Item(2, "/api/preview", "url", "https://www.iana.org/help");
        assertEquals("/api/preview?url=https%3A%2F%2Fwww.iana.org%2Fhelp", preview.requestTarget());
        assertEquals("url=https://www.iana.org/help", preview.appArgs());

        BenignCorpus.Item ko = new BenignCorpus.Item(3, "/api/products/search", "keyword", "노트북 15인치");
        assertEquals("/api/products/search?keyword=%EB%85%B8%ED%8A%B8%EB%B6%81+15%EC%9D%B8%EC%B9%98", ko.requestTarget());
        assertEquals(List.of("keyword=노트북 15인치"), List.of(ko.appArgs()));
    }
}
