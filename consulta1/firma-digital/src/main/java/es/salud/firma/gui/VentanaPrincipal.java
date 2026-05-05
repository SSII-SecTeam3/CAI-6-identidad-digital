package es.salud.firma.gui;

import es.salud.firma.model.CertificadoInfo;
import es.salud.firma.model.ResultadoVerificacion;
import es.salud.firma.service.FirmaService;
import es.salud.firma.service.VerificacionService;
import es.salud.firma.util.CargadorCertificado;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Ventana principal de la aplicación de Firma Digital.
 *
 * <h2>Arquitectura de la GUI</h2>
 * <p>La ventana se divide en tres paneles:</p>
 * <ol>
 *   <li><b>Panel de Selección:</b> Campos para seleccionar el documento y el certificado.</li>
 *   <li><b>Panel de Acciones:</b> Botones para firmar y verificar.</li>
 *   <li><b>Consola de Log:</b> Área de texto donde se muestran todos los resultados.</li>
 * </ol>
 *
 * <h2>Thread Safety</h2>
 * <p>Las operaciones criptográficas (firma/verificación) se ejecutan en un
 * {@link SwingWorker} para no bloquear el Event Dispatch Thread (EDT)
 * y evitar que la GUI se congele durante operaciones largas.</p>
 */
public class VentanaPrincipal extends JFrame {

    private static final Logger log = LoggerFactory.getLogger(VentanaPrincipal.class);

    private static final DateTimeFormatter FMT_LOG =
            DateTimeFormatter.ofPattern("HH:mm:ss");

    // --- Componentes de selección ---
    private JTextField campoDocumento;
    private JTextField campoCertificado;
    private JPasswordField campoContrasena;

    // --- Botones de acción ---
    private JButton btnFirmar;
    private JButton btnVerificar;

    // --- Consola de log ---
    private JTextArea areaLog;

    // --- Servicios (inyectados directamente en la PoC) ---
    private final FirmaService firmaService = new FirmaService();
    private final VerificacionService verificacionService = new VerificacionService();

    public VentanaPrincipal() {
        super("Firma Digital — Servicio de Salud (PoC v1.0)");
        initUI();
        configurarVentana();
    }

    // =========================================================================
    // INICIALIZACIÓN DE LA UI
    // =========================================================================

    private void initUI() {
        // Panel raíz con padding exterior
        JPanel panelRaiz = new JPanel(new BorderLayout(10, 10));
        panelRaiz.setBorder(new EmptyBorder(12, 12, 12, 12));

        // --- Panel superior: selección + acciones ---
        JPanel panelSuperior = new JPanel(new BorderLayout(10, 10));
        panelSuperior.add(crearPanelSeleccion(), BorderLayout.CENTER);
        panelSuperior.add(crearPanelAcciones(), BorderLayout.EAST);

        panelRaiz.add(panelSuperior, BorderLayout.NORTH);
        panelRaiz.add(crearPanelLog(), BorderLayout.CENTER);

        setContentPane(panelRaiz);
    }

    private JPanel crearPanelSeleccion() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("1. Selección de ficheros"));

        GridBagConstraints etiqueta = new GridBagConstraints();
        etiqueta.anchor = GridBagConstraints.WEST;
        etiqueta.insets = new Insets(4, 4, 4, 8);
        etiqueta.gridx = 0;

        GridBagConstraints campo = new GridBagConstraints();
        campo.fill = GridBagConstraints.HORIZONTAL;
        campo.weightx = 1.0;
        campo.insets = new Insets(4, 0, 4, 4);
        campo.gridx = 1;

        GridBagConstraints boton = new GridBagConstraints();
        boton.insets = new Insets(4, 0, 4, 0);
        boton.gridx = 2;

        // --- Fila 0: Documento ---
        etiqueta.gridy = 0;
        campo.gridy = 0;
        boton.gridy = 0;

        campoDocumento = new JTextField(30);
        campoDocumento.setEditable(false);
        campoDocumento.setToolTipText("Fichero PDF o XML a firmar/verificar");

        JButton btnSeleccionarDoc = new JButton("Examinar…");
        btnSeleccionarDoc.addActionListener(e -> seleccionarDocumento());

        panel.add(new JLabel("Documento (PDF/XML):"), etiqueta);
        panel.add(campoDocumento, campo);
        panel.add(btnSeleccionarDoc, boton);

        // --- Fila 1: Certificado ---
        etiqueta.gridy = 1;
        campo.gridy = 1;
        boton.gridy = 1;

        campoCertificado = new JTextField(30);
        campoCertificado.setEditable(false);
        campoCertificado.setToolTipText("Fichero de certificado digital (.p12 o .pfx)");

        JButton btnSeleccionarCert = new JButton("Examinar…");
        btnSeleccionarCert.addActionListener(e -> seleccionarCertificado());

        panel.add(new JLabel("Certificado (.p12/.pfx):"), etiqueta);
        panel.add(campoCertificado, campo);
        panel.add(btnSeleccionarCert, boton);

        // --- Fila 2: Contraseña ---
        etiqueta.gridy = 2;
        campo.gridy = 2;

        campoContrasena = new JPasswordField(30);
        campoContrasena.setToolTipText("Contraseña del certificado PKCS#12");

        // Mostrar/ocultar contraseña
        JCheckBox chkMostrar = new JCheckBox("Ver");
        chkMostrar.addActionListener(e ->
                campoContrasena.setEchoChar(chkMostrar.isSelected() ? (char) 0 : '•')
        );
        boton.gridy = 2;

        panel.add(new JLabel("Contraseña del certificado:"), etiqueta);
        panel.add(campoContrasena, campo);
        panel.add(chkMostrar, boton);

        return panel;
    }

    private JPanel crearPanelAcciones() {
        JPanel panel = new JPanel(new GridLayout(3, 1, 8, 8));
        panel.setBorder(new TitledBorder("2. Acciones"));
        panel.setPreferredSize(new Dimension(160, 0));

        btnFirmar = new JButton("✍  Firmar Documento");
        btnFirmar.setToolTipText("Firma el documento seleccionado con el certificado");
        btnFirmar.addActionListener(this::accionFirmar);
        styleBotonPrimario(btnFirmar);

        btnVerificar = new JButton("🔍  Verificar Firma");
        btnVerificar.setToolTipText("Verifica la(s) firma(s) del documento seleccionado");
        btnVerificar.addActionListener(this::accionVerificar);
        styleBotonSecundario(btnVerificar);

        JButton btnLimpiarLog = new JButton("🗑  Limpiar Log");
        btnLimpiarLog.addActionListener(e -> areaLog.setText(""));

        panel.add(btnFirmar);
        panel.add(btnVerificar);
        panel.add(btnLimpiarLog);

        return panel;
    }

    private JPanel crearPanelLog() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("3. Consola de resultados"));

        areaLog = new JTextArea(18, 80);
        areaLog.setEditable(false);
        areaLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        areaLog.setBackground(new Color(30, 30, 30));
        areaLog.setForeground(new Color(220, 220, 220));
        areaLog.setCaretColor(Color.WHITE);
        areaLog.setLineWrap(true);
        areaLog.setWrapStyleWord(true);

        JScrollPane scroll = new JScrollPane(areaLog);
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scroll, BorderLayout.CENTER);

        // Mensaje inicial
        log("Sistema de Firma Digital iniciado.");
        log("Proveedor criptográfico: BouncyCastle (ECC 256-bits + RSA)");
        log("────────────────────────────────────────────────────────────");

        return panel;
    }

    private void configurarVentana() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pack();
        setMinimumSize(new Dimension(800, 550));
        setLocationRelativeTo(null); // Centrar en pantalla
    }

    // =========================================================================
    // SELECCIÓN DE FICHEROS
    // =========================================================================

    private void seleccionarDocumento() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Seleccionar documento a firmar/verificar");
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Documentos (PDF, XML)", "pdf", "xml"
        ));
        chooser.setAcceptAllFileFilterUsed(false);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            campoDocumento.setText(chooser.getSelectedFile().getAbsolutePath());
            log("Documento seleccionado: " + chooser.getSelectedFile().getName());
        }
    }

    private void seleccionarCertificado() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Seleccionar certificado PKCS#12");
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Certificados PKCS#12 (*.p12, *.pfx)", "p12", "pfx"
        ));
        chooser.setAcceptAllFileFilterUsed(false);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            campoCertificado.setText(chooser.getSelectedFile().getAbsolutePath());
            log("Certificado seleccionado: " + chooser.getSelectedFile().getName());
        }
    }

    // =========================================================================
    // ACCIONES: FIRMAR
    // =========================================================================

    private void accionFirmar(ActionEvent e) {
        // Validar que los campos requeridos estén rellenos
        String rutaDoc = campoDocumento.getText().trim();
        String rutaCert = campoCertificado.getText().trim();
        char[] contrasena = campoContrasena.getPassword();

        if (rutaDoc.isEmpty()) {
            mostrarError("Debe seleccionar un documento antes de firmar.");
            return;
        }
        if (rutaCert.isEmpty()) {
            mostrarError("Debe seleccionar un certificado (.p12/.pfx) antes de firmar.");
            return;
        }
        if (contrasena.length == 0) {
            mostrarError("Debe introducir la contraseña del certificado.");
            return;
        }

        File ficheroDoc  = new File(rutaDoc);
        File ficheroCert = new File(rutaCert);

        // Ejecutar en SwingWorker para no bloquear la GUI
        new SwingWorker<File, String>() {

            @Override
            protected File doInBackground() throws Exception {
                publish("\n════ INICIANDO PROCESO DE FIRMA ════");
                publish("Cargando certificado: " + ficheroCert.getName());

                // 1. Cargar el certificado PKCS#12
                CertificadoInfo cert = CargadorCertificado.cargar(ficheroCert, contrasena);
                publish("Certificado cargado correctamente:");
                publish(cert.resumen());

                // 2. Firmar según el tipo de documento
                String nombre = ficheroDoc.getName().toLowerCase();
                File resultado;
                if (nombre.endsWith(".pdf")) {
                    publish("Firmando PDF…");
                    resultado = firmaService.firmarPDF(ficheroDoc, cert);
                } else if (nombre.endsWith(".xml")) {
                    publish("Firmando XML (firma Enveloped)…");
                    resultado = firmaService.firmarXML(ficheroDoc, cert);
                } else {
                    throw new IllegalArgumentException(
                            "Tipo de fichero no soportado. Use .pdf o .xml"
                    );
                }
                return resultado;
            }

            @Override
            protected void process(List<String> chunks) {
                chunks.forEach(VentanaPrincipal.this::log);
            }

            @Override
            protected void done() {
                setActionsEnabled(true);
                try {
                    File resultado = get();
                    log("✓ FIRMA COMPLETADA EXITOSAMENTE");
                    log("  Documento firmado guardado en:");
                    log("  " + resultado.getAbsolutePath());
                    log("────────────────────────────────────────");
                    JOptionPane.showMessageDialog(
                            VentanaPrincipal.this,
                            "Documento firmado guardado en:\n" + resultado.getAbsolutePath(),
                            "Firma completada",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    manejarExcepcion("FIRMA", ex);
                }
            }
        }.execute();

        setActionsEnabled(false);
    }

    // =========================================================================
    // ACCIONES: VERIFICAR
    // =========================================================================

    private void accionVerificar(ActionEvent e) {
        String rutaDoc = campoDocumento.getText().trim();

        if (rutaDoc.isEmpty()) {
            mostrarError("Debe seleccionar el documento firmado a verificar.");
            return;
        }

        File ficheroDoc = new File(rutaDoc);

        new SwingWorker<List<ResultadoVerificacion>, String>() {

            @Override
            protected List<ResultadoVerificacion> doInBackground() throws Exception {
                publish("\n════ INICIANDO PROCESO DE VERIFICACIÓN ════");
                publish("Documento: " + ficheroDoc.getName());

                String nombre = ficheroDoc.getName().toLowerCase();
                if (nombre.endsWith(".pdf")) {
                    publish("Modo: Verificación de firma PDF (CMS/PKCS#7)");
                    return verificacionService.verificarPDF(ficheroDoc);
                } else if (nombre.endsWith(".xml")) {
                    publish("Modo: Verificación de firma XML (XMLDSig Enveloped)");
                    return verificacionService.verificarXML(ficheroDoc);
                } else {
                    throw new IllegalArgumentException(
                            "Tipo de fichero no soportado para verificación. Use .pdf o .xml"
                    );
                }
            }

            @Override
            protected void process(List<String> chunks) {
                chunks.forEach(VentanaPrincipal.this::log);
            }

            @Override
            protected void done() {
                setActionsEnabled(true);
                try {
                    List<ResultadoVerificacion> resultados = get();
                    boolean todasValidas = resultados.stream()
                            .allMatch(ResultadoVerificacion::valida);

                    resultados.forEach(r -> log(r.resumenCompleto()));
                    log("────────────────────────────────────────");

                    if (todasValidas) {
                        log("✓ RESULTADO FINAL: TODAS LAS FIRMAS SON VÁLIDAS");
                        JOptionPane.showMessageDialog(
                                VentanaPrincipal.this,
                                "✓ Todas las firmas son válidas.\nEl documento es auténtico e íntegro.",
                                "Verificación correcta",
                                JOptionPane.INFORMATION_MESSAGE
                        );
                    } else {
                        log("✗ RESULTADO FINAL: UNA O MÁS FIRMAS SON INVÁLIDAS");
                        JOptionPane.showMessageDialog(
                                VentanaPrincipal.this,
                                "✗ Una o más firmas son inválidas.\nEl documento puede haber sido modificado.",
                                "Verificación fallida",
                                JOptionPane.WARNING_MESSAGE
                        );
                    }
                } catch (Exception ex) {
                    manejarExcepcion("VERIFICACIÓN", ex);
                }
            }
        }.execute();

        setActionsEnabled(false);
    }

    // =========================================================================
    // UTILIDADES DE GUI
    // =========================================================================

    /**
     * Añade una línea al área de log con timestamp y desplaza al final automáticamente.
     * DEBE ser llamado desde el EDT.
     */
    private void log(String mensaje) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> log(mensaje));
            return;
        }
        String timestamp = LocalDateTime.now().format(FMT_LOG);
        areaLog.append("[" + timestamp + "] " + mensaje + "\n");
        // Auto-scroll al final
        areaLog.setCaretPosition(areaLog.getDocument().getLength());
    }

    /**
     * Maneja excepciones de forma centralizada, mostrando mensajes amigables
     * sin stacktrace completo en la GUI (el stacktrace va al log del sistema).
     */
    private void manejarExcepcion(String operacion, Exception ex) {
        // Desempaquetar ExecutionException de SwingWorker
        Throwable causa = ex;
        if (ex instanceof java.util.concurrent.ExecutionException && ex.getCause() != null) {
            causa = ex.getCause();
        }

        String mensajeUsuario;
        String nivel;

        if (causa instanceof SecurityException) {
            mensajeUsuario = "Contraseña incorrecta para el certificado PKCS#12.";
            nivel = "SEGURIDAD";
        } else if (causa instanceof java.security.cert.CertificateExpiredException) {
            mensajeUsuario = "El certificado ha CADUCADO. No se puede usar para firmar.";
            nivel = "CERTIFICADO";
        } else if (causa instanceof java.security.cert.CertificateNotYetValidException) {
            mensajeUsuario = "El certificado aún NO ES VÁLIDO (fecha de inicio no alcanzada).";
            nivel = "CERTIFICADO";
        } else if (causa instanceof java.io.IOException) {
            mensajeUsuario = "Error de E/S: " + causa.getMessage();
            nivel = "E/S";
        } else if (causa instanceof IllegalArgumentException) {
            mensajeUsuario = causa.getMessage();
            nivel = "PARÁMETRO";
        } else {
            mensajeUsuario = causa != null ? causa.getMessage() : ex.getMessage();
            nivel = "ERROR";
        }

        log("✗ ERROR DE " + nivel + " EN " + operacion + ": " + mensajeUsuario);
        log("  (Ver logs del sistema para detalles técnicos)");
        log("────────────────────────────────────────");

        // Log técnico completo para el desarrollador
        log.error("Error en {}: {}", operacion, mensajeUsuario, causa);

        JOptionPane.showMessageDialog(
                this,
                "Error en " + operacion + ":\n\n" + mensajeUsuario,
                "Error",
                JOptionPane.ERROR_MESSAGE
        );
    }

    private void mostrarError(String mensaje) {
        JOptionPane.showMessageDialog(this, mensaje, "Datos incompletos", JOptionPane.WARNING_MESSAGE);
    }

    private void setActionsEnabled(boolean enabled) {
        btnFirmar.setEnabled(enabled);
        btnVerificar.setEnabled(enabled);
    }

    private void styleBotonPrimario(JButton btn) {
        btn.setBackground(new Color(0, 100, 180));
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD));
    }

    private void styleBotonSecundario(JButton btn) {
        btn.setBackground(new Color(0, 140, 80));
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD));
    }
}
