FROM openjdk:8-jdk-alpine AS build
COPY . /src/
USER root
RUN mkdir -p  /output && /src/gradlew clean assemble -p /src/
RUN cp src/build/libs/recaptcha-authenticator-1.0.jar output/recaptcha-authenticator.jar


FROM sleighzy/keycloak:15.0.2-arm64 AS final

COPY --from=build /output/recaptcha-authenticator.jar /opt/jboss/keycloak/standalone/deployments/recaptcha-authenticator.jar
COPY resources/login.ftl /opt/jboss/keycloak/themes/base/login/login.ftl
COPY resources/realm-export.json /opt/jboss/resources/realm-export.json

WORKDIR /opt/jboss/keycloak

RUN bin/add-user-keycloak.sh -u admin -p admin

ENTRYPOINT ["bin/standalone.sh"]
