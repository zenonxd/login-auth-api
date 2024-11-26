FROM amazoncorretto:21

LABEL authors="olavo"

WORKDIR /app

# Copiar o JAR gerado pelo build para dentro do contêiner
# O arquivo JAR será copiado para o contêiner. O caminho depende de onde você gerar o JAR.
COPY target/login-auth-api-0.0.1-SNAPSHOT.jar app.jar

# Expor a porta onde o Spring Boot será executado
EXPOSE 8080

CMD ["java", "-jar", "app.jar"]