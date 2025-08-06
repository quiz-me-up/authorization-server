FROM quizmeup/maven:latest AS java-builder

WORKDIR /usr/src/app

COPY pom.xml .

RUN mvn dependency:go-offline

COPY . .

RUN mvn clean install

FROM eclipse-temurin:21-jre-alpine AS java-runtime

ARG TARGET_DIR=target

# Créer un utilisateur non-root pour la sécurité
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# Définir le répertoire de travail
WORKDIR /usr/src/app

# Copier le JAR depuis le chemin spécifié
COPY --from=java-builder /usr/src/app/${TARGET_DIR}/*.jar app.jar

# Changer le propriétaire du fichier
RUN chown appuser:appgroup app.jar

# Basculer vers l'utilisateur non-root
USER appuser

# Point d'entrée de l'application
ENTRYPOINT ["sh", "-c", "java -jar app.jar"]