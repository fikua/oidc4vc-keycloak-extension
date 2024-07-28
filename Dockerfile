# Stage 1: Build the project
FROM docker.io/gradle:8.4.0 AS builder
ARG SKIP_TESTS=false
WORKDIR /home/gradle/src
# Copy the project files
COPY gradle /home/gradle/src/gradle
COPY checkstyle /home/gradle/src/checkstyle
COPY api /home/gradle/src/api
COPY build.gradle settings.gradle /home/gradle/src/
COPY src /home/gradle/src/src
# Clean the project and generate the OpenAPI client
RUN gradle clean --no-daemon
RUN gradle openApiGenerate --no-daemon
# Verify the generated sources
RUN ls /home/gradle/src/build/generated
# Build the project
RUN if [ "$SKIP_TESTS" = "true" ]; then \
    gradle build --no-daemon -x test; \
  else \
    gradle build --no-daemon; \
  fi

# Verify the contents of the build/libs directory
RUN ls /home/gradle/src/build/libs
# Stage 2: Build the final image
FROM quay.io/keycloak/keycloak:25.0.2
USER root
RUN ["sed", "-i", "s/SHA1, //g", "/usr/share/crypto-policies/DEFAULT/java.txt"]
USER 1000
WORKDIR /app
# Copy the JAR file from the builder image
COPY --from=builder /home/gradle/src/build/libs/oidc4vc-keycloak-extension-0.0.1.jar /opt/keycloak/providers/
# Copy the Realm configuration file to the Keycloak configuration directory
COPY /import /opt/keycloak/data/import
EXPOSE 8080
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", \
            "start-dev", \
            "--health-enabled=true", \
            "--metrics-enabled=true", \
            "--log-level=INFO", \
            "--import-realm"]
