FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .

COPY catalog-service/pom.xml catalog-service/
COPY checkout-service/pom.xml checkout-service/
COPY user-service/pom.xml user-service/
COPY shared-utils/pom.xml shared-utils/
COPY discovery-service/pom.xml discovery-service/
COPY api-gateway/pom.xml api-gateway/
COPY auth-server/pom.xml auth-server/
COPY config-server/pom.xml config-server/

COPY shared-utils/src shared-utils/src

RUN mvn clean install -DskipTests -pl shared-utils -am
RUN mvn dependency:go-offline -B
COPY . .
RUN mvn clean package -DskipTests -pl discovery-service -am

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
ENV ARTIFACT_NAME=discovery-service
COPY --from=build /app/${ARTIFACT_NAME}/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
