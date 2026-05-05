package es.salud.firma.util;

import es.salud.firma.model.CertificadoInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Utilidad para cargar y extraer credenciales desde ficheros PKCS#12 (.p12 / .pfx).
 *
 * <p><b>Seguridad:</b> La contraseña se recibe como {@code char[]} (no {@code String})
 * para poder borrarla de memoria tras su uso, reduciendo la ventana de exposición.</p>
 *
 * <p><b>Soporte ECC:</b> Al estar BouncyCastle registrado como proveedor principal
 * (ver {@code Main.java}), este cargador maneja transparentemente tanto claves RSA
 * como claves de Curva Elíptica (ECDSA P-256).</p>
 */
public class CargadorCertificado {

    private static final Logger log = LoggerFactory.getLogger(CargadorCertificado.class);

    // PKCS#12 es el formato estándar para ficheros .p12 y .pfx
    private static final String TIPO_KEYSTORE = "PKCS12";

    private CargadorCertificado() {
        // Clase de utilidad estática, no instanciable
    }

    /**
     * Carga un fichero PKCS#12 y extrae el primer par de claves encontrado.
     *
     * @param ficheroP12  Fichero .p12 o .pfx a cargar.
     * @param contrasena  Contraseña del fichero (se sobreescribe a ceros tras su uso).
     * @return {@link CertificadoInfo} con el certificado, la clave privada y el alias.
     * @throws IOException          Si el fichero no existe o no se puede leer.
     * @throws CertificateException Si el certificado está corrupto o tiene formato inválido.
     * @throws SecurityException    Si la contraseña es incorrecta.
     * @throws KeyStoreException    Si el keystore está corrupto o vacío.
     */
    public static CertificadoInfo cargar(File ficheroP12, char[] contrasena)
            throws IOException, CertificateException, SecurityException, KeyStoreException {

        validarFichero(ficheroP12);

        KeyStore keyStore;
        try {
            // BouncyCastle es el proveedor registrado, gestionará ECC automáticamente
            keyStore = KeyStore.getInstance(TIPO_KEYSTORE);
        } catch (KeyStoreException e) {
            throw new KeyStoreException("No se puede obtener instancia de KeyStore PKCS12: " + e.getMessage(), e);
        }

        // Cargar el fichero PKCS#12 con la contraseña proporcionada
        try (FileInputStream fis = new FileInputStream(ficheroP12)) {
            keyStore.load(fis, contrasena);
            log.debug("Fichero PKCS#12 cargado: {}", ficheroP12.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException("Algoritmo de integridad del keystore no disponible: " + e.getMessage(), e);
        } catch (IOException e) {
            // IOException con causa específica indica contraseña incorrecta en PKCS#12
            if (e.getCause() != null && e.getCause().getMessage() != null
                    && e.getCause().getMessage().contains("mac check")) {
                throw new SecurityException("Contraseña incorrecta para el fichero PKCS#12.", e);
            }
            // Otros errores de E/S (fichero corrupto, truncado, etc.)
            throw new IOException("Error al leer el fichero PKCS#12. Puede estar corrupto: " + e.getMessage(), e);
        } finally {
            // Sobreescribir la contraseña en memoria para minimizar exposición
            java.util.Arrays.fill(contrasena, '\0');
        }

        return extraerPrimerEntrada(keyStore, ficheroP12.getName());
    }

    /**
     * Itera sobre los alias del keystore y devuelve el primero que contenga
     * una clave privada (ignora entradas de sólo certificado).
     */
    private static CertificadoInfo extraerPrimerEntrada(KeyStore keyStore, String nombreFichero)
            throws KeyStoreException, SecurityException {

        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (!keyStore.isKeyEntry(alias)) {
                log.debug("Alias '{}' no contiene clave privada, saltando.", alias);
                continue;
            }

            try {
                // null como contraseña: en PKCS#12 la clave ya fue desencriptada al cargar el store
                PrivateKey clavePrivada = (PrivateKey) keyStore.getKey(alias, null);
                X509Certificate certificado = (X509Certificate) keyStore.getCertificate(alias);

                if (clavePrivada == null) {
                    log.warn("El alias '{}' tiene entrada de clave pero la clave es nula.", alias);
                    continue;
                }
                if (certificado == null) {
                    log.warn("El alias '{}' no tiene certificado asociado.", alias);
                    continue;
                }

                log.info("Certificado cargado - Alias: {}, Algoritmo: {}, Sujeto: {}",
                        alias, clavePrivada.getAlgorithm(),
                        certificado.getSubjectX500Principal().getName());

                return new CertificadoInfo(certificado, clavePrivada, alias);

            } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
                log.error("Error al recuperar la clave del alias '{}': {}", alias, e.getMessage());
                throw new SecurityException("No se puede recuperar la clave privada del certificado: " + e.getMessage(), e);
            }
        }

        throw new KeyStoreException("El fichero PKCS#12 '" + nombreFichero
                + "' no contiene ninguna clave privada válida.");
    }

    private static void validarFichero(File fichero) throws IOException {
        if (fichero == null || !fichero.exists()) {
            throw new IOException("El fichero de certificado no existe: " + fichero);
        }
        if (!fichero.isFile() || !fichero.canRead()) {
            throw new IOException("El fichero no es legible: " + fichero.getAbsolutePath());
        }
        String nombre = fichero.getName().toLowerCase();
        if (!nombre.endsWith(".p12") && !nombre.endsWith(".pfx")) {
            log.warn("El fichero '{}' no tiene extensión .p12 o .pfx. Se intentará cargar igualmente.", fichero.getName());
        }
    }
}
