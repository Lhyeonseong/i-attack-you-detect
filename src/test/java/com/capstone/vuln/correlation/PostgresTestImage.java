package com.capstone.vuln.correlation;

/**
 * Testcontainers 가 쓰는 postgres 이미지 — 운영 compose 와 같은 digest 로 고정(ADR-S4-03 D1).
 *
 * <p>운영: docker/docker-compose.yml postgres 서비스 'image: postgres:${POSTGRES_VERSION}@sha256:…',
 * docker/.env POSTGRES_VERSION=16.15-trixie. 운영 이미지를 바꿀 때 이 값도 함께 바꾼다.
 *
 * <p>태그 없이 digest 만 쓴다: Testcontainers DockerImageName 은 'repo:tag@sha256:…' 을 repo 'postgres:16.15-trixie' 로
 * 읽어 PostgreSQLContainer 의 'postgres' 호환 검사에서 실패한다. digest 는 내용 주소라 가리키는 이미지는 같다.
 */
public final class PostgresTestImage {

    /** = postgres:16.15-trixie@sha256:ca0bd484… */
    public static final String IMAGE =
            "postgres@sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d";

    private PostgresTestImage() {
    }
}
