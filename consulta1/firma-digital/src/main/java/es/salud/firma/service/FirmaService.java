package es.salud.firma.service;

import es.salud.firma.model.CertificadoInfo;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;

/**
 * Servicio de FIRMA de documentos PDF y XML.
 *
 * <h2>PDF (PAdES básico)</h2>
 * <p>Utiliza Apache PDFBox para incrustar una firma CMS/PKCS#7 dentro
 * del PDF. El flujo es:</p>
 * <ol>
 *   <li>Abrir el PDF con PDFBox.</li>
 *   <li>Crear un objeto {@link PDSignature} con los metadatos.</li>
 *   <li>Registrar un {@link SignatureInterface} que, en su método
 *       {@code sign()}, construye el CMS SignedData con BouncyCastle.</li>
 *   <li>Guardar el PDF firmado con {@code saveIncrementalForExternalSigning}.</li>
 * </ol>
 *
 * <h2>XML (XMLDSig Enveloped)</h2>
 * <p>Utiliza Apache Santuario (xmlsec) para crear una firma
 * {@code <ds:Signature>} incrustada dentro del propio XML (enveloped).
 * El flujo es:</p>
 * <ol>
 *   <li>Parsear el XML a un DOM {@link Document}.</li>
 *   <li>Crear un objeto {@link XMLSignature} apuntando al elemento raíz.</li>
 *   <li>Añadir una transformada {@code ENVELOPED_SIGNATURE} para excluir
 *       el propio nodo de firma del cálculo del hash.</li>
 *   <li>Firmar con la clave privada del certificado.</li>
 *   <li>Serializar el DOM modificado al fichero de salida.</li>
 * </ol>
 *
 * <h2>Soporte ECC</h2>
 * <p>El algoritmo de firma se selecciona dinámicamente según el tipo de
 * clave: {@code SHA256withECDSA} para ECC y {@code SHA256withRSA} para RSA.
 * BouncyCastle gestiona ambos algoritmos.</p>
 */
public class FirmaService {

    private static final Logger log = LoggerFactory.getLogger(FirmaService.class);

    /** Tamaño reservado para la firma CMS dentro del PDF (bytes). 32 KB es suficiente para ECC y RSA. */
    private static final int PREFERRED_SIGNATURE_SIZE = 32768;

    // Inicializar Apache Santuario una sola vez al cargar la clase
    static {
        Init.init();
        log.debug("Apache XML Security (Santuario) inicializado.");
    }

    // -------------------------------------------------------------------------
    // API PÚBLICA
    // -------------------------------------------------------------------------

    /**
     * Firma un documento PDF y lo guarda como {@code <nombre_original>_signed.pdf}.
     *
     * @param ficheroEntrada Fichero PDF a firmar.
     * @param cert           Credenciales del firmante (certificado + clave privada).
     * @return Fichero PDF firmado.
     * @throws Exception Si ocurre cualquier error durante la firma.
     */
    public File firmarPDF(File ficheroEntrada, CertificadoInfo cert) throws Exception {
        File ficheroSalida = generarNombreSalida(ficheroEntrada, "_signed.pdf");
        log.info("[PDF] Iniciando firma de: {} -> {}", ficheroEntrada.getName(), ficheroSalida.getName());

        try (PDDocument documento = PDDocument.load(ficheroEntrada);
             FileOutputStream fos = new FileOutputStream(ficheroSalida)) {

            // Crear el objeto de metadatos de la firma
            PDSignature firma = new PDSignature();
            firma.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            firma.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            firma.setName(extraerNombreCN(cert));
            firma.setReason("Firma electrónica - Servicio de Salud");
            firma.setLocation("España");
            firma.setSignDate(Calendar.getInstance());

            // Configurar el espacio reservado para la firma CMS en el PDF
            SignatureOptions opciones = new SignatureOptions();
            opciones.setPreferredSignatureSize(PREFERRED_SIGNATURE_SIZE);

            // Registrar la interfaz de firma: PDFBox llamará a sign() con los bytes
            // del PDF que deben ser firmados (todo excepto el espacio reservado)
            documento.addSignature(firma, buildSignatureInterface(cert), opciones);

            // Guardar de forma incremental (append) preservando el contenido original
            documento.saveIncremental(fos);
        }

        log.info("[PDF] Firma completada. Fichero de salida: {}", ficheroSalida.getAbsolutePath());
        return ficheroSalida;
    }

    /**
     * Firma un documento XML (firma Enveloped) y lo guarda como
     * {@code <nombre_original>_signed.xml}.
     *
     * @param ficheroEntrada Fichero XML a firmar.
     * @param cert           Credenciales del firmante.
     * @return Fichero XML firmado.
     * @throws Exception Si ocurre cualquier error durante la firma.
     */
    public File firmarXML(File ficheroEntrada, CertificadoInfo cert) throws Exception {
        File ficheroSalida = generarNombreSalida(ficheroEntrada, "_signed.xml");
        log.info("[XML] Iniciando firma de: {} -> {}", ficheroEntrada.getName(), ficheroSalida.getName());

        // 1. Parsear XML a DOM
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // Obligatorio para XMLDSig
        // Seguridad: deshabilitar DTD para prevenir XXE
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc;
        try (FileInputStream fis = new FileInputStream(ficheroEntrada)) {
            doc = dbf.newDocumentBuilder().parse(fis);
        }

        // 2. Determinar el algoritmo de firma según el tipo de clave
        String algoritmoFirma = seleccionarAlgoritmoFirmaXML(cert);
        log.debug("[XML] Algoritmo de firma seleccionado: {}", algoritmoFirma);

        // 3. Crear el objeto XMLSignature (referencia al elemento raíz: URI="")
        Element raiz = doc.getDocumentElement();
        String baseUri = ficheroEntrada.toURI().toString();

        XMLSignature xmlSig = new XMLSignature(doc, baseUri, algoritmoFirma);

        // 4. Añadir la transformada ENVELOPED: excluye el nodo <ds:Signature>
        //    del cálculo del hash, evitando referencia circular.
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        // Canonicalización C14N para normalizar el XML antes del hash
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Referencia vacía ("") = firma el documento completo
        xmlSig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        // 5. Incrustar el certificado en el KeyInfo del XML firmado
        xmlSig.addKeyInfo(cert.certificado());
        xmlSig.addKeyInfo(cert.certificado().getPublicKey());

        // 6. Adjuntar el nodo <ds:Signature> al elemento raíz del documento
        raiz.appendChild(xmlSig.getElement());

        // 7. Firmar con la clave privada
        xmlSig.sign(cert.clavePrivada());

        // 8. Serializar el DOM modificado a fichero
        serializarDOM(doc, ficheroSalida);

        log.info("[XML] Firma completada. Fichero de salida: {}", ficheroSalida.getAbsolutePath());
        return ficheroSalida;
    }

    // -------------------------------------------------------------------------
    // MÉTODOS PRIVADOS
    // -------------------------------------------------------------------------

    /**
     * Construye el {@link SignatureInterface} que PDFBox usará para obtener
     * los bytes CMS de la firma. Se usa BouncyCastle para construir el CMS.
     */
    private SignatureInterface buildSignatureInterface(CertificadoInfo cert) {
        return contenidoAFirmar -> {
            try {
                // contenidoAFirmar es el InputStream con los bytes del PDF (sin el espacio de firma)
                byte[] bytes = contenidoAFirmar.readAllBytes();
                String algoritmoFirma = seleccionarAlgoritmoFirmaCMS(cert);
                log.debug("[PDF] Construyendo CMS con algoritmo: {}", algoritmoFirma);

                // Construir el generador de CMS SignedData con BouncyCastle
                CMSSignedDataGenerator generador = new CMSSignedDataGenerator();

                // ContentSigner: encapsula la clave privada y el algoritmo
                ContentSigner contentSigner = new JcaContentSignerBuilder(algoritmoFirma)
                        .setProvider("BC") // Usar explícitamente BouncyCastle
                        .build(cert.clavePrivada());

                // Añadir la información del firmante (certificado + algoritmos)
                generador.addSignerInfoGenerator(
                        new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                        ).build(contentSigner, cert.certificado())
                );

                // Incrustar el certificado completo en el CMS (necesario para verificación offline)
                generador.addCertificates(new JcaCertStore(
                        Collections.singletonList(cert.certificado())
                ));

                // Generar CMS detached (el contenido NO está dentro del CMS, sino en el PDF)
                CMSProcessableByteArray contenidoCMS = new CMSProcessableByteArray(bytes);
                CMSSignedData signedData = generador.generate(contenidoCMS, false);

                return signedData.getEncoded();

            } catch (Exception e) {
                // Capturamos OperatorCreationException, CMSException, etc. y las envolvemos
                throw new java.io.IOException("Error al generar la firma CMS con BouncyCastle", e);
            }
        };
    }


    /**
     * Selecciona el algoritmo de firma CMS/PKCS#7 según el tipo de clave privada.
     * - ECC  → SHA256withECDSA
     * - RSA  → SHA256withRSA
     */
    private String seleccionarAlgoritmoFirmaCMS(CertificadoInfo cert) {
        String tipoAlgoritmo = cert.clavePrivada().getAlgorithm().toUpperCase();
        if ("EC".equals(tipoAlgoritmo) || "ECDSA".equals(tipoAlgoritmo)) {
            return "SHA256withECDSA";
        } else if ("RSA".equals(tipoAlgoritmo)) {
            return "SHA256withRSA";
        } else {
            log.warn("Tipo de clave no reconocido '{}', usando SHA256withRSA por defecto.", tipoAlgoritmo);
            return "SHA256withRSA";
        }
    }

    /**
     * Selecciona el identificador de algoritmo XMLDSig según el tipo de clave privada.
     * - ECC → http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
     * - RSA → http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     */
    private String seleccionarAlgoritmoFirmaXML(CertificadoInfo cert) {
        String tipoAlgoritmo = cert.clavePrivada().getAlgorithm().toUpperCase();
        if ("EC".equals(tipoAlgoritmo) || "ECDSA".equals(tipoAlgoritmo)) {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
        } else if ("RSA".equals(tipoAlgoritmo)) {
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
        } else {
            log.warn("Tipo de clave no reconocido '{}', usando RSA-SHA256 por defecto.", tipoAlgoritmo);
            return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
        }
    }

    /** Serializa un DOM Document a un fichero XML con codificación UTF-8. */
    private void serializarDOM(Document doc, File ficheroSalida) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        // Seguridad: deshabilitar acceso externo en TransformerFactory
        tf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(javax.xml.transform.OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes");

        try (FileOutputStream fos = new FileOutputStream(ficheroSalida)) {
            transformer.transform(new DOMSource(doc), new StreamResult(fos));
        }
    }

    /** Genera el nombre del fichero de salida añadiendo un sufijo antes de la extensión. */
    private File generarNombreSalida(File entrada, String sufijo) {
        String nombre = entrada.getName();
        int punto = nombre.lastIndexOf('.');
        String sinExtension = (punto > 0) ? nombre.substring(0, punto) : nombre;
        return new File(entrada.getParent(), sinExtension + sufijo);
    }

    /** Extrae el CN (Common Name) del sujeto del certificado para los metadatos PDF. */
    private String extraerNombreCN(CertificadoInfo cert) {
        String dn = cert.certificado().getSubjectX500Principal().getName();
        for (String parte : dn.split(",")) {
            String p = parte.trim();
            if (p.startsWith("CN=")) {
                return p.substring(3);
            }
        }
        return dn; // Devolver el DN completo si no hay CN
    }
}
