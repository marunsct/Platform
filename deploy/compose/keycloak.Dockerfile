# Keycloak with Matura's extension (token mapper). Build context: repository root.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY keycloak/extensions/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY keycloak/extensions/src ./src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:26.4
COPY --from=build /src/target/matura-keycloak-*.jar /opt/keycloak/providers/
