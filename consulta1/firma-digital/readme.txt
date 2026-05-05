Pasos para ejecutar el programa de firmado / verificación de firmas:

*Nota: requiere tener Java y Maven instalados en el sistema.

1. Acceder a la carpeta <firma-digital>
2. Compilar programa (genera el .jar ejecutable): mvn clean package -DskipTests
3. Ejecutar el .jar: java -jar target/firma-digital.jar
Ejecutar con más memoria (para documentos pesados): java -Xmx512m -jar target/firma-digital.jar
