FROM eclipse-temurin:17-jdk-jammy as build

WORKDIR /app

COPY mvnw* .
COPY .mvn .mvn
COPY pom.xml .
RUN ./mvnw -q -DskipTests package -DskipITs || true

COPY src src
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]

