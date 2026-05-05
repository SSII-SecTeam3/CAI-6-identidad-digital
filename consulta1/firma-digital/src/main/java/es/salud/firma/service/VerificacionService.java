package es.salud.firma.service;

import es.salud.firma.model.ResultadoVerificacion;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Servicio de VERIFICACIÓN de firmas en documentos PDF y XML.
 *
 * <h2>¿Qué verifica exactamente?</h2>
 * <p>La verificación criptográfica realiza dos comprobaciones matemáticas:</p>
 * <ol>
 *   <li><b>Integridad del documento:</b> Se recalcula el hash (SHA-256) del
 *       contenido firmado y se compara con el hash almacenado en la firma.
 *       Si no coinciden, el documento ha sido modificado.</li>
 *   <li><b>Autenticidad de la firma:</b> Se verifica que la firma digital
 *       (cifrado asimétrico) fue creada con la clave privada correspondiente
 *       a la clave pública del certificado incrustado.</li>
 * </ol>
 *
 * <p><b>Nota sobre confianza:</b> Esta PoC verifica la integridad matemática
 * pero NO valida la cadena de confianza PKI (OCSP/CRL). En producción, se
 * debería validar también que el certificado no está revocado y que el
 * emisor es una CA reconocida por el Ministerio de Sanidad.</p>
 */
public class VerificacionService {

    private static final Logger log = LoggerFactory.getLogger(VerificacionService.class);
    private static final DateTimeFormatter FMT_FECHA =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss").withZone(ZoneId.systemDefault());

    static {
        Init.init();
    }

    // -------------------------------------------------------------------------
    // API PÚBLICA
    // -------------------------------------------------------------------------

    /**
     * Verifica todas las firmas presentes en un documento PDF.
     *
     * @param fichero Fichero PDF firmado.
     * @return Lista de {@link ResultadoVerificacion}, uno por cada firma encontrada.
     * @throws Exception Si el fichero no puede leerse o no es un PDF válido.
     */
    public List<ResultadoVerificacion> verificarPDF(File fichero) throws Exception {
        log.info("[PDF] Iniciando verificación de: {}", fichero.getName());
        List<ResultadoVerificacion> resultados = new ArrayList<>();

        try (PDDocument documento = PDDocument.load(fichero)) {
            List<PDSignature> firmas = documento.getSignatureDictionaries();

            if (firmas.isEmpty()) {
                log.warn("[PDF] El documento no contiene ninguna firma.");
                return Collections.singletonList(
                        ResultadoVerificacion.sinFirma("El PDF no contiene ninguna firma digital.")
                );
            }

            log.info("[PDF] Se encontraron {} firma(s) en el documento.", firmas.size());

            for (int i = 0; i < firmas.size(); i++) {
                PDSignature firma = firmas.get(i);
                ResultadoVerificacion resultado = verificarFirmaPDF(fichero, firma, i + 1);
                resultados.add(resultado);
            }
        }

        return resultados;
    }

    /**
     * Verifica la firma XMLDSig Enveloped de un documento XML.
     *
     * @param fichero Fichero XML firmado.
     * @return Lista de {@link ResultadoVerificacion}, uno por cada {@code <ds:Signature>} encontrado.
     * @throws Exception Si el fichero no puede parsearse.
     */
    public List<ResultadoVerificacion> verificarXML(File fichero) throws Exception {
        log.info("[XML] Iniciando verificación de: {}", fichero.getName());
        List<ResultadoVerificacion> resultados = new ArrayList<>();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        Document doc;
        try (FileInputStream fis = new FileInputStream(fichero)) {
            doc = dbf.newDocumentBuilder().parse(fis);
        }

        // Buscar todos los nodos <ds:Signature> en el documento
        NodeList nodosSignature = doc.getElementsByTagNameNS(
                org.apache.xml.security.utils.Constants.SignatureSpecNS, "Signature"
        );

        if (nodosSignature.getLength() == 0) {
            log.warn("[XML] No se encontró ningún nodo <ds:Signature> en el documento.");
            return Collections.singletonList(
                    ResultadoVerificacion.sinFirma("El XML no contiene ninguna firma digital (nodo <ds:Signature> ausente).")
            );
        }

        log.info("[XML] Se encontraron {} firma(s) en el documento.", nodosSignature.getLength());

        for (int i = 0; i < nodosSignature.getLength(); i++) {
            Element elementoFirma = (Element) nodosSignature.item(i);
            ResultadoVerificacion resultado = verificarFirmaXML(elementoFirma, fichero, i + 1);
            resultados.add(resultado);
        }

        return resultados;
    }

    // -------------------------------------------------------------------------
    // VERIFICACIÓN PDF (CMS/PKCS#7)
    // -------------------------------------------------------------------------

    private ResultadoVerificacion verificarFirmaPDF(File fichero, PDSignature pdFirma, int indice)
            throws Exception {

        String etiqueta = String.format("Firma PDF #%d", indice);
        log.debug("[PDF] Procesando {}", etiqueta);

        // Extraer los bytes del CMS (la firma en sí) y los bytes del PDF cubiertos por la firma
        byte[] bytesFirma;
        byte[] bytesContenido;

        try (FileInputStream fis = new FileInputStream(fichero)) {
            bytesFirma = pdFirma.getContents(fis);
        }
        try (FileInputStream fis = new FileInputStream(fichero)) {
            // getSignedContent devuelve los bytes del PDF EXCLUYENDO el espacio de la firma
            bytesContenido = pdFirma.getSignedContent(fis);
        }

        // Parsear el CMS SignedData
        CMSSignedData cmsSignedData = new CMSSignedData(
                new org.bouncycastle.cms.CMSProcessableByteArray(bytesContenido),
                bytesFirma
        );

        // Obtener el almacén de certificados incrustados en el CMS
        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        StringBuilder detalles = new StringBuilder();
        boolean todasValidas = true;
        X509Certificate certFirmante = null;

        for (SignerInformation signer : signers.getSigners()) {
            // Buscar el certificado del firmante en el store
            Collection<X509CertificateHolder> certMatches =
                    certStore.getMatches(signer.getSID());

            if (certMatches.isEmpty()) {
                detalles.append("  ⚠ No se encontró el certificado del firmante en el CMS.\n");
                todasValidas = false;
                continue;
            }

            X509CertificateHolder certHolder = certMatches.iterator().next();
            certFirmante = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certHolder);

            // *** VERIFICACIÓN CRIPTOGRÁFICA ***
            // Comprueba que la firma fue creada con la clave privada del certificado
            // y que los datos firmados (hash) coinciden con el contenido actual del PDF.
            boolean valida = signer.verify(
                    new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC")
                            .build(certFirmante)
            );

            detalles.append(formatearInfoCertificado(certFirmante));
            detalles.append(String.format("  Algoritmo firma : %s%n", signer.getEncryptionAlgOID()));
            detalles.append(String.format("  Algoritmo digest: %s%n", signer.getDigestAlgOID()));
            detalles.append(String.format("  Integridad      : %s%n", valida ? "✓ VÁLIDA" : "✗ INVÁLIDA"));

            if (!valida) todasValidas = false;
        }

        // Metadatos de la firma del PDF
        if (pdFirma.getSignDate() != null) {
            String fechaFirma = FMT_FECHA.format(pdFirma.getSignDate().toInstant());
            detalles.append(String.format("  Fecha de firma  : %s%n", fechaFirma));
        }
        if (pdFirma.getReason() != null) {
            detalles.append(String.format("  Motivo          : %s%n", pdFirma.getReason()));
        }

        return new ResultadoVerificacion(etiqueta, todasValidas, detalles.toString(), certFirmante);
    }

    // -------------------------------------------------------------------------
    // VERIFICACIÓN XML (XMLDSig)
    // -------------------------------------------------------------------------

    private ResultadoVerificacion verificarFirmaXML(Element elementoFirma, File fichero, int indice)
            throws Exception {

        String etiqueta = String.format("Firma XML #%d", indice);
        log.debug("[XML] Procesando {}", etiqueta);

        String baseUri = fichero.toURI().toString();
        XMLSignature xmlSig = new XMLSignature(elementoFirma, baseUri);

        // Extraer el certificado incrustado en el <ds:KeyInfo>
        KeyInfo keyInfo = xmlSig.getKeyInfo();
        X509Certificate certFirmante = null;

        if (keyInfo != null) {
            certFirmante = keyInfo.getX509Certificate();
        }

        if (certFirmante == null) {
            return new ResultadoVerificacion(
                    etiqueta, false,
                    "  ✗ No se encontró certificado en el KeyInfo del XML firmado.\n",
                    null
            );
        }

        // *** VERIFICACIÓN CRIPTOGRÁFICA XMLDSig ***
        // Santuario recalcula el hash del contenido referenciado y verifica
        // la firma con la clave pública del certificado.
        boolean valida = xmlSig.checkSignatureValue(certFirmante.getPublicKey());

        StringBuilder detalles = new StringBuilder();
        detalles.append(formatearInfoCertificado(certFirmante));
        detalles.append(String.format("  Algoritmo firma : %s%n", xmlSig.getSignedInfo().getSignatureMethodURI()));
        detalles.append(String.format("  Integridad      : %s%n", valida ? "✓ VÁLIDA" : "✗ INVÁLIDA (documento modificado)"));

        return new ResultadoVerificacion(etiqueta, valida, detalles.toString(), certFirmante);
    }

    // -------------------------------------------------------------------------
    // UTILIDADES
    // -------------------------------------------------------------------------

    private String formatearInfoCertificado(X509Certificate cert) {
        String sujeto = cert.getSubjectX500Principal().getName();
        String emisor = cert.getIssuerX500Principal().getName();
        String validoHasta = FMT_FECHA.format(cert.getNotAfter().toInstant());

        return String.format(
                "  Firmante        : %s%n" +
                "  Emisor (CA)     : %s%n" +
                "  Válido hasta    : %s%n" +
                "  Nº Serie        : %s%n",
                sujeto, emisor, validoHasta,
                cert.getSerialNumber().toString(16).toUpperCase()
        );
    }
}
