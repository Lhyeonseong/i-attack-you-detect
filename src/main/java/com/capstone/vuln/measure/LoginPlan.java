package com.capstone.vuln.measure;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * login 정상 코퍼스 계획 (ADR-S4-01 v2.0 R17 f) — detections/corpus/benign/login-plan-*.csv.
 * 열: seq,credential_ref,username,scenario(NORMAL|TYPO). 비밀번호 열은 없다 — 코드·파일·로그·DB 어디에도 두지 않는다(CWE-798).
 * scenario 는 전송자(사람) 스크립트가 정상/오타를 정하는 메타이며 적재·대조에는 쓰지 않는다. seq 는 1부터 빈틈없이 증가해야 한다.
 */
public record LoginPlan(List<Entry> entries) {

    public static final String ENDPOINT = "/api/auth/login";
    /** 앱 로그 http_request.args 의 파라미터명 — benign_endpoint.param('username')과 같다(AttackLogger 는 username=<값>으로 기록) */
    public static final String PARAM = "username";
    public static final String HEADER = "seq,credential_ref,username,scenario";

    /** 계획 1행 — username 은 계정 별칭(비밀번호 아님) */
    public record Entry(int seq, String credentialRef, String username, String scenario) {
    }

    public int size() {
        return entries.size();
    }

    public Entry bySeq(int seq) {
        return entries.get(seq - 1);
    }

    public static LoginPlan load(Path csv) {
        List<String> lines;
        try {
            lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<String> rows = new ArrayList<>();
        for (String raw : lines) {
            String line = raw.strip();
            if (!line.isEmpty() && !line.startsWith("#")) {
                rows.add(line);
            }
        }
        if (rows.isEmpty() || !HEADER.equals(rows.get(0))) {
            throw new IllegalStateException("login-plan 헤더가 '" + HEADER + "' 이 아니다: " + csv);
        }
        List<Entry> entries = new ArrayList<>();
        for (int i = 1; i < rows.size(); i++) {
            String[] f = rows.get(i).split(",", -1);
            if (f.length != 4) {
                throw new IllegalStateException("login-plan 행 열 수가 4가 아니다 (행 " + (i + 1) + "): " + rows.get(i));
            }
            int seq;
            try {
                seq = Integer.parseInt(f[0].strip());
            } catch (NumberFormatException e) {
                throw new IllegalStateException("login-plan seq 가 정수가 아니다 (행 " + (i + 1) + "): " + f[0]);
            }
            if (seq != entries.size() + 1) {
                throw new IllegalStateException("login-plan seq 가 1부터 빈틈없이 증가하지 않는다: " + seq + " (기대 "
                        + (entries.size() + 1) + ")");
            }
            String scenario = f[3].strip();
            if (!"NORMAL".equals(scenario) && !"TYPO".equals(scenario)) {
                throw new IllegalStateException("login-plan scenario 는 NORMAL|TYPO (행 " + (i + 1) + "): " + scenario);
            }
            String username = f[2].strip();
            if (username.isEmpty()) {
                throw new IllegalStateException("login-plan username 이 비었다 (행 " + (i + 1) + ")");
            }
            entries.add(new Entry(seq, f[1].strip(), username, scenario));
        }
        if (entries.isEmpty()) {
            throw new IllegalStateException("login-plan 에 요청 행이 없다: " + csv);
        }
        return new LoginPlan(List.copyOf(entries));
    }
}
