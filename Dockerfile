# Multi-stage build: Maven build, then JRE runtime.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q package -DskipTests

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 app
WORKDIR /app
COPY --from=build /build/target/pd-security-*.jar app.jar
RUN mkdir -p /app/logs && chown -R app:app /app
USER app
EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseZGC", "-Xms512m", "-Xmx2g", "-jar", "app.jar"]