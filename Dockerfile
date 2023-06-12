# syntax=docker/dockerfile:experimental
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace/app

COPY . /workspace/app
#RUN --mount=type=cache,target=/root/.gradle ./gradlew clean build
#RUN mkdir -p build/dependency && (cd build/dependency; jar -xf ../libs/*-SNAPSHOT.jar)


RUN --mount=type=secret,id=USERNAME\
    export USERNAME=$(cat /run/secrets/USERNAME)
RUN --mount=type=secret,id=PERSONAL_ACCESS_TOKEN && \
    export PERSONAL_ACCESS_TOKEN=$(cat /run/secrets/PERSONAL_ACCESS_TOKEN) && \
    --mount=type=cache,target=/root/.gradle ./gradlew clean build
RUN  mkdir -p build/dependency && (cd build/dependency; jar -xf ../libs/*-SNAPSHOT.jar)

FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
ARG DEPENDENCY=/workspace/app/build/dependency
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app
ENTRYPOINT ["java","-cp","app:app/lib/*","me.sonam.auth.DefaultAuthorizationServerApplication"]

LABEL org.opencontainers.image.source https://github.com/sonamsamdupkhangsar/email-rest-service

#ENTRYPOINT [ "java", "-jar", "/app/email-rest-service.jar"]

