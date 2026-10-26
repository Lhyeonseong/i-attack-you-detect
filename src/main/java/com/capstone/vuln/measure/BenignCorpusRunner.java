package com.capstone.vuln.measure;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 정상 코퍼스를 manifest 순서대로 순차 전송한다 (R17 a — 동시 1건, 요청 사이 간격, 기본 200 ms).
 * 요청마다 전송·응답 시각과 HTTP 상태를 남긴다(전송 실패 = -1, 계속 진행). 이 시각 창이 앱 로그·NIDS 대조 기준이다(R17 c·R18 c).
 */
public class BenignCorpusRunner {

    public static final Duration DEFAULT_INTERVAL = Duration.ofMillis(200);

    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration d) throws InterruptedException;
    }

    private final BenignSender sender;
    private final TimeSource time;
    private final Sleeper sleeper;
    private final Duration interval;

    public BenignCorpusRunner(BenignSender sender, TimeSource time, Sleeper sleeper, Duration interval) {
        this.sender = sender;
        this.time = time;
        this.sleeper = sleeper;
        this.interval = interval;
    }

    public List<BenignSent> run(List<BenignCorpus.Item> items) {
        List<BenignSent> sent = new ArrayList<>(items.size());
        for (int i = 0; i < items.size(); i++) {
            BenignCorpus.Item it = items.get(i);
            String target = it.requestTarget();
            Instant sentAt = Instant.ofEpochMilli(time.millis());
            int status;
            try {
                status = sender.send(target);
            } catch (IOException e) {
                status = -1;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("정상 코퍼스 전송 중단됨 (seq " + it.seq() + ")", e);
            }
            Instant respondedAt = Instant.ofEpochMilli(time.millis());
            sent.add(new BenignSent(it.seq(), it.endpoint(), target, it.appArgs(), sentAt, respondedAt, status));
            if (i < items.size() - 1) {
                try {
                    sleeper.sleep(interval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("정상 코퍼스 전송 중단됨 (seq " + it.seq() + " 뒤)", e);
                }
            }
        }
        return sent;
    }
}
