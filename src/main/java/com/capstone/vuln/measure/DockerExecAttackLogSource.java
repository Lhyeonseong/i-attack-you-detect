package com.capstone.vuln.measure;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * attack.json.log 를 named volume(target_logs) 안에서 읽는다 → docker compose exec 로 cat (결정 A, S3-2 경로).
 * 측정 도구는 호스트에서 실행되므로 docker 호출이 가능하다(b-1 스모크와 동일 전제).
 * S4-4: 같은 방식으로 suricata 서비스의 eve.json 도 읽는다(EveTelemetryReader, 읽기 전용) — 메시지는 logPath 를 쓴다.
 */
public class DockerExecAttackLogSource implements AttackLogSource {

    private final String composeFile;
    private final String project;
    private final String service;
    private final String logPath;

    public DockerExecAttackLogSource(String composeFile, String project, String service, String logPath) {
        this.composeFile = composeFile;
        this.project = project;
        this.service = service;
        this.logPath = logPath;
    }

    @Override
    public String read() {
        ProcessBuilder pb = new ProcessBuilder(
                "docker", "compose", "-f", composeFile, "-p", project,
                "exec", "-T", service, "cat", logPath);
        pb.redirectErrorStream(false);
        try {
            Process process = pb.start();
            byte[] out = process.getInputStream().readAllBytes();
            boolean done = process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) {
                process.destroyForcibly();
                throw new IllegalStateException(logPath + " 읽기 타임아웃 (docker exec)");
            }
            if (process.exitValue() != 0) {
                String err = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                throw new IllegalStateException(logPath + " 읽기 실패 (exit="
                        + process.exitValue() + "): " + err);
            }
            return new String(out, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("docker exec 실행 실패", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(logPath + " 읽기 중단됨", e);
        }
    }
}
