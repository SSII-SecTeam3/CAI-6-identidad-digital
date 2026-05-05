package es.salud.firma;

import es.salud.firma.gui.VentanaPrincipal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.security.Security;

/**
 * Punto de entrada de la aplicación de Firma Digital.
 *
 * <p>Responsabilidades del arranque:
 * <ul>
 *   <li>Registrar BouncyCastle como proveedor de seguridad (posición 1 = máxima prioridad)
 *       para garantizar soporte de ECC P-256 y algoritmos avanzados.</li>
 *   <li>Inicializar la interfaz Swing en el Event Dispatch Thread (EDT).</li>
 * </ul>
 *
 * @author Arquitectura de Software - Servicio de Salud
 * @version 1.0.0-POC
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {

        // ----------------------------------------------------------------
        // 1. Registrar BouncyCastle como proveedor de seguridad prioritario.
        //    Esto es CRÍTICO para:
        //    - Certificados ECC (ECDSA) con curvas P-256, P-384, P-521
        //    - Algoritmos de firma SHA256withECDSA, SHA384withECDSA
        //    - Lectura de keystores PKCS#12 con claves ECC
        //    insertAt(1) lo coloca ANTES del proveedor Sun para ECC
        // ----------------------------------------------------------------
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            log.info("Proveedor BouncyCastle registrado correctamente (posición 1). " +
                     "Soporte ECC 256-bits activado.");
        } else {
            log.info("Proveedor BouncyCastle ya estaba registrado.");
        }

        // ----------------------------------------------------------------
        // 2. Inicializar la GUI en el Event Dispatch Thread (EDT).
        //    Obligatorio para thread-safety en Swing.
        // ----------------------------------------------------------------
        SwingUtilities.invokeLater(() -> {
            try {
                // Intentar usar el Look & Feel del sistema operativo
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                log.warn("No se pudo aplicar el Look & Feel del sistema: {}", e.getMessage());
                // Continuamos con el L&F por defecto de Swing (Metal)
            }

            VentanaPrincipal ventana = new VentanaPrincipal();
            ventana.setVisible(true);
            log.info("Aplicación de Firma Digital iniciada.");
        });
    }
}
