FROM eclipse-temurin:17-jre
WORKDIR /app
COPY build/libs/vulnerable-webapp-0.0.1-SNAPSHOT.jar app.jar
RUN mkdir -p /var/app/uploads
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]

