package com.capstone.validationapi.web;

import com.capstone.validationapi.error.ApiExceptions.BadRequestException;
import com.capstone.validationapi.error.ApiExceptions.NotFoundException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * 화면용 정적 데이터(ADR-S4-04): gaps·findings·display-names. 숫자 없음(숫자는 스냅샷 조회).
 * classpath:content/<name>.json 을 그대로 전달. 허용 목록만(경로 조작 차단).
 */
@RestController
@RequestMapping("/api/v1/content")
public class ContentController {

    private static final Set<String> ALLOWED = Set.of("gaps", "findings", "display-names");

    @GetMapping(value = "/{name}", produces = MediaType.APPLICATION_JSON_VALUE)
    public String content(@PathVariable String name) {
        if (!ALLOWED.contains(name)) {
            throw new BadRequestException("허용되지 않은 content: " + name);
        }
        ClassPathResource res = new ClassPathResource("content/" + name + ".json");
        if (!res.exists()) {
            throw new NotFoundException("content 없음: " + name);
        }
        try (InputStream in = res.getInputStream()) {
            return StreamUtils.copyToString(in, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new NotFoundException("content 읽기 실패: " + name);
        }
    }
}
