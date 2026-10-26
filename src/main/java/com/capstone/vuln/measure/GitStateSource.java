package com.capstone.vuln.measure;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** 측정 시점 git 상태 seam — 운영은 git CLI, 테스트는 고정값 */
@FunctionalInterface
public interface GitStateSource {

    GitState read();

    /** repoDir 에서 git rev-parse HEAD / git status --porcelain 실행. 실패하면 run 을 열지 않는다(예외) */
    static GitStateSource cli(Path repoDir) {
        return () -> new GitState(run(repoDir, "git", "rev-parse", "HEAD").trim(),
                !run(repoDir, "git", "status", "--porcelain").isBlank());
    }

    private static String run(Path dir, String... command) {
        try {
            Process p = new ProcessBuilder(List.of(command)).directory(dir.toFile()).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!p.waitFor(30, TimeUnit.SECONDS) || p.exitValue() != 0) {
                throw new IllegalStateException(String.join(" ", command) + " 실패: " + out.trim());
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException(String.join(" ", command) + " 실행 불가", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(String.join(" ", command) + " 중단됨", e);
        }
    }
}
