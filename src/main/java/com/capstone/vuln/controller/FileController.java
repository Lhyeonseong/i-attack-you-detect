package com.capstone.vuln.controller;

import com.capstone.vuln.attack.AttackObservation;
import com.capstone.vuln.attack.ValidationContext;
import com.capstone.vuln.correlation.*;
import com.capstone.vuln.file.PathTraversalInput;
import com.capstone.vuln.file.PathTraversalValidator;
import com.capstone.vuln.logging.AttackLogger;
import com.capstone.vuln.logging.HttpExchange;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.*;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/files")
public class FileController {

    @Value("${app.upload-dir}")
    private String uploadDir;

    private static final String DOWNLOAD_PATH = "/api/files/download";

    @Autowired private CalderaCorrelationExtractor extractor;
    @Autowired private AttackLogger attackLogger;
    @Autowired private PathTraversalValidator pathTraversalValidator;

    /**
     * [VULNERABLE] Path Traversal - 의도적 경로 검증 누락
     */
    @GetMapping("/download")
    public ResponseEntity<?> download(@RequestParam String filename, HttpServletRequest request) {
        String requestId = UUID.randomUUID().toString();
        Instant requestTime = Instant.now();
        long start = System.currentTimeMillis();
        CorrelationInfo correlation = extractor.extract(request);
        String args = "filename=" + filename;
        attackLogger.logRequest(requestId, DOWNLOAD_PATH, "GET",
                correlation, null, args);

        try {
            Path filePath = Paths.get(uploadDir + "/" + filename);
            File file = filePath.toFile();

            if (!file.exists()) {
                attackLogger.logResponse(requestId, DOWNLOAD_PATH, correlation, 404,
                        "NOT_FOUND", "path=" + file.getAbsolutePath());
                String body = "File not found at: " + file.getAbsolutePath();
                logHttpActivity(requestId, requestTime, start, correlation, args, 404, utf8Length(body),
                        PathTraversalInput.notFound(filePath, Paths.get(uploadDir)));
                return ResponseEntity.status(404).body(body);
            }

            byte[] content = Files.readAllBytes(filePath);
            String typeGuess = guessContentType(content);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDisposition(
                    ContentDisposition.attachment().filename(filename).build()
            );

            attackLogger.logResponse(requestId, DOWNLOAD_PATH, correlation, 200,
                    "FILE_RETURNED", "type=" + typeGuess + " size=" + content.length);
            logHttpActivity(requestId, requestTime, start, correlation, args, 200, content.length,
                    PathTraversalInput.fileReturned(filePath, Paths.get(uploadDir), content.length, typeGuess));
            return ResponseEntity.ok().headers(headers).body(content);

        } catch (Exception e) {
            attackLogger.logResponse(requestId, DOWNLOAD_PATH, correlation, 500,
                    "ERROR", "msg=" + e.getMessage() + " uploadDir=" + uploadDir);
            String body = "Error reading file: " + e.getMessage() + " at path: " + uploadDir;
            logHttpActivity(requestId, requestTime, start, correlation, args, 500, utf8Length(body),
                    PathTraversalInput.error(Paths.get(uploadDir)));
            return ResponseEntity.status(500).body(body);
        }
    }

    /**
     * OCSF HTTP Activity JSON 로그 (기존 pipe 로그와 병행)
     * - Validator 결과는 validation 에만 기록되고 응답 본문/상태코드에는 영향을 주지 않는다
     */
    private void logHttpActivity(String requestId, Instant requestTime, long start, CorrelationInfo correlation,
                                 String args, int statusCode, long bodyLength, PathTraversalInput input) {
        long latencyMs = System.currentTimeMillis() - start;
        AttackObservation observation = pathTraversalValidator.validate(
                new ValidationContext<>(requestId, correlation, requestTime, statusCode, input));
        HttpExchange exchange = new HttpExchange(requestTime, "GET", DOWNLOAD_PATH,
                correlation.getUserAgent(), args, statusCode, latencyMs, bodyLength);
        attackLogger.logHttpActivity(requestId, exchange, correlation, observation);
    }

    private static long utf8Length(String body) {
        return body.getBytes(StandardCharsets.UTF_8).length;
    }

    /**
     * 응답 본문 앞 256바이트 기준 텍스트/바이너리 추정
     * - 4단계 보정 시 텍스트 응답만 필터링하여 분석 가능
     */
    private String guessContentType(byte[] content) {
        int len = Math.min(content.length, 256);
        String preview = new String(content, 0, len, StandardCharsets.UTF_8);
        long nonPrintable = preview.chars()
                .filter(c -> c < 0x20 && c != '\n' && c != '\r' && c != '\t')
                .count();
        return nonPrintable < 10 ? "text" : "binary";
    }
}