package com.capstone.validationapi.web;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Service
public class ImdsLogService {

    private static final Path LOG_PATH = Path.of("/var/log/mock-imds/access.log");

    private static final String SSRF_PATH =
            "/latest/meta-data/iam/security-credentials/mock-iam-role";

    private static final Pattern ACCESS_LOG = Pattern.compile(
            "\\[(\\d{2}/[A-Za-z]{3}/\\d{4} \\d{2}:\\d{2}:\\d{2})\\] " +
            "\"GET " + Pattern.quote(SSRF_PATH) + " HTTP/[^\"]+\" 200 "
    );

    private static final DateTimeFormatter LOG_TIME =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy HH:mm:ss", Locale.ENGLISH);

    public long countRequests(OffsetDateTime startedAt, OffsetDateTime endedAt) {
        if (startedAt == null || endedAt == null || !Files.isRegularFile(LOG_PATH)) {
            return 0L;
        }

        Instant start = startedAt.toInstant();
        Instant end = endedAt.toInstant();

        try (Stream<String> lines = Files.lines(LOG_PATH)) {
            return lines.filter(line -> isMatchingRequest(line, start, end)).count();
        } catch (IOException e) {
            return 0L;
        }
    }

    private boolean isMatchingRequest(String line, Instant start, Instant end) {
        Matcher m = ACCESS_LOG.matcher(line);
        if (!m.find()) {
            return false;
        }

        try {
            // python http.server 컨테이너 로그는 컨테이너 로컬 시간(UTC) 기준.
            Instant t = LocalDateTime.parse(m.group(1), LOG_TIME)
                    .toInstant(ZoneOffset.UTC);

            return !t.isBefore(start) && !t.isAfter(end);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
