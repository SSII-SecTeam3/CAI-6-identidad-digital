package es.salud.firma.model;

import java.security.cert.X509Certificate;

/**
 * Resultado inmutable de una operación de verificación de firma.
 *
 * <p>Nota: clase normal (no record) para compatibilidad con Java 11.</p>
 */
public final class ResultadoVerificacion {

    private final String etiqueta;
    private final boolean valida;
    private final String detalles;
    private final X509Certificate certificado;

    public ResultadoVerificacion(String etiqueta, boolean valida,
                                  String detalles, X509Certificate certificado) {
        this.etiqueta     = etiqueta;
        this.valida       = valida;
        this.detalles     = detalles;
        this.certificado  = certificado;
    }

    public String           etiqueta()    { return etiqueta; }
    public boolean          valida()      { return valida; }
    public String           detalles()    { return detalles; }
    public X509Certificate  certificado() { return certificado; }

    /**
     * Factory para el caso en que el documento no contiene ninguna firma.
     */
    public static ResultadoVerificacion sinFirma(String mensaje) {
        return new ResultadoVerificacion("Sin firma", false, "  " + mensaje, null);
    }

    /**
     * Genera el resumen completo para mostrar en la consola de log de la GUI.
     */
    public String resumenCompleto() {
        String estado = valida
                ? "✓ FIRMA VÁLIDA — La firma es auténtica y el documento no ha sido alterado."
                : "✗ FIRMA INVÁLIDA — El documento puede haber sido modificado o la firma es ilegítima.";

        return String.format(
                "--- %s ---%n" +
                "%s%n" +
                "%s",
                etiqueta, estado, detalles
        );
    }
}
