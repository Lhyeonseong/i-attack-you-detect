# 최신 main의 루트 src/를 직접 빌드하는 Dockerfile
# build context는 프로젝트 루트(../../)를 사용
# 빌드는 gradle wrapper(gradle/wrapper/gradle-wrapper.properties)가 하므로 JDK 이미지면 된다. 태그는 digest 로 고정
FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a AS builder
WORKDIR /workspace
COPY build.gradle settings.gradle gradlew ./
COPY gradle ./gradle
COPY src ./src
RUN chmod +x gradlew && ./gradlew bootJar --no-daemon

FROM eclipse-temurin:17-jre@sha256:e04fa72be13b257a59fdec6dc14af78c8f80f035d3c1ed4e03e45552a231d4c8
WORKDIR /app
COPY --from=builder /workspace/build/libs/*.jar app.jar
COPY docker/services/target-web/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN mkdir -p /opt/target/uploads /var/log/target \
    && chmod +x /app/docker-entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
