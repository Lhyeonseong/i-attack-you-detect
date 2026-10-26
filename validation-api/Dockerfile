# validation-api 다단계 빌드 (ADR-S4-02 D10). build context = validation-api/
# 이미지 digest 고정(ADR-S4-03 D1). node digest 는 현성 /tmp/s4-6-buildx.log 와 대조.
# temurin digest 는 target-web(docker/services/target-web/Dockerfile) 과 동일 재사용.

# ── ① UI 빌드 (node, digest 고정) ──────────────────────────────────────────────
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS ui
WORKDIR /ui
# lock 먼저 복사 → npm ci(--ignore-scripts, D10). lock 은 /tmp/s4-6-ui-verify.sh 로 미리 생성·커밋.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --ignore-scripts
COPY ui/ ./
# tsc --noEmit && vite build (package.json build 스크립트). 산출 /ui/dist
RUN npm run build

# ── ② 백엔드 빌드 (JDK 17, target-web 패턴 digest) ──────────────────────────────
FROM eclipse-temurin:17-jdk@sha256:fe947d993c32dd9cf651a4353a6ed723c2370b3a9d034ea4cab4775404ea531a AS build
WORKDIR /workspace
COPY gradlew settings.gradle build.gradle ./
COPY gradle ./gradle
COPY src ./src
# UI 산출물을 같은 출처 정적 자원으로(D9). .dockerignore 로 호스트 static/ 은 제외됨.
COPY --from=ui /ui/dist ./src/main/resources/static
RUN chmod +x gradlew && ./gradlew --no-daemon clean bootJar cyclonedxDirectBom

# ── ③ 런타임 (JRE 17, 비루트) ───────────────────────────────────────────────────
FROM eclipse-temurin:17-jre@sha256:e04fa72be13b257a59fdec6dc14af78c8f80f035d3c1ed4e03e45552a231d4c8
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar
# D8: SBOM 은 파일로만 포함(엔드포인트 미노출)
COPY --from=build /workspace/build/reports/bom.json /app/sbom/bom.json
# uid·gid 둘 다 10001 고정(useradd -r 은 gid 를 시스템 기본값으로 만들어 마운트 key.pem 그룹(10001) 불일치 발생).
RUN groupadd -g 10001 vapi \
    && useradd -r -u 10001 -g 10001 -s /usr/sbin/nologin vapi \
    && chown -R vapi:vapi /app
USER vapi
EXPOSE 8090
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
