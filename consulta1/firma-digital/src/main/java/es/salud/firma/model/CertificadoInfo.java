package es.salud.firma.model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Contenedor inmutable que encapsula las credenciales extraídas de un fichero PKCS#12.
 *
 * <p>Se usa como objeto de transferencia entre {@code CargadorCertificado}
 * y los servicios de firma.</p>
 *
 * <p>Nota: clase normal (no record) para compatibilidad con Java 11.</p>
 */
public final class CertificadoInfo {

    private final X509Certificate certificado;
    private final PrivateKey clavePrivada;
    private final String alias;

    public CertificadoInfo(X509Certificate certificado, PrivateKey clavePrivada, String alias) {
        this.certificado  = certificado;
        this.clavePrivada = clavePrivada;
        this.alias        = alias;
    }

    public X509Certificate certificado()   { return certificado; }
    public PrivateKey       clavePrivada() { return clavePrivada; }
    public String           alias()        { return alias; }

    /**
     * Devuelve un resumen legible de los metadatos del certificado.
     * Útil para mostrar en el área de log de la GUI.
     */
    public String resumen() {
        String algoritmo   = clavePrivada.getAlgorithm();
        String sujeto      = certificado.getSubjectX500Principal().getName();
        String emisor      = certificado.getIssuerX500Principal().getName();
        String validoHasta = certificado.getNotAfter().toString();

        return String.format(
                "  Alias       : %s%n" +
                "  Algoritmo   : %s%n" +
                "  Sujeto      : %s%n" +
                "  Emisor      : %s%n" +
                "  Válido hasta: %s",
                alias, algoritmo, sujeto, emisor, validoHasta
        );
    }
}
