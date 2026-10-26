package com.capstone.vuln.measure;

import java.io.IOException;

/** 정상 요청 1건 전송 → HTTP 상태 (R17 a: 브라우저형 UA, Caldera 헤더 없음). 테스트는 가짜 구현 */
@FunctionalInterface
public interface BenignSender {

    String USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

    int send(String requestTarget) throws IOException, InterruptedException;
}
