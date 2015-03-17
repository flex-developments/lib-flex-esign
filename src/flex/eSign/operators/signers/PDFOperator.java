/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments en gmail
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments en gmail | flopez en suscerte gob ve
 * Ing. Yessica De Ascencao - yessicadeascencao en gmail | ydeascencao en suscerte gob ve
 *
 * Este programa es software libre; Usted puede usarlo bajo los terminos de la
 * licencia de software GPL version 2.0 de la Free Software Foundation.
 *
 * Este programa se distribuye con la esperanza de que sea util, pero SIN
 * NINGUNA GARANTIA; tampoco las implicitas garantias de MERCANTILIDAD o
 * ADECUACION A UN PROPOSITO PARTICULAR.
 * Consulte la licencia GPL para mas detalles. Usted debe recibir una copia
 * de la GPL junto con este programa; si no, escriba a la Free Software
 * Foundation Inc. 51 Franklin Street,5 Piso, Boston, MA 02110-1301, USA.
 */

package flex.eSign.operators.signers;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import flex.eSign.helpers.ProviderHelper;
import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.helpers.CertificateHelper;
import flex.eSign.helpers.exceptions.AlgorithmsHelperException;
import flex.eSign.helpers.exceptions.CertificateHelperException;
import flex.eSign.i18n.I18n;
import flex.eSign.operators.exceptions.PDFOperadorException;
import flex.helpers.DateHelper;
import flex.helpers.exceptions.DateHelperException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

/**
 * PDFOperator
 * Operador que efectua acciones de calculo de hash e insercion de firma electronica
 * sobre documentos PDF.
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class PDFOperator {
    
    public static PdfReader getPdfReader(
        File pdfFile,
        String readPass
    ) throws PDFOperadorException {
        
        try {
            if(readPass == null) return new PdfReader(pdfFile.getAbsolutePath());
            else return new PdfReader(pdfFile.getAbsolutePath(), readPass.getBytes());
            
        } catch (IOException ex) {
            throw new PDFOperadorException(ex);
        }
    }
    
    //////////////////////// Modificación de PDF ///////////////////////////////
    /**
     * 
     * @param stamper
     * @param text
     * @param page
     * @param posX
     * @param posY
     * @param rotation
     * @param textSize
     * @param typeFace Se pueden obtener los posibles valores desde la clase com.itextpdf.text.pdf.BaseFont\n\tValor por defecto = BaseFont.TIMES_ROMAN
     * @param encoderTypeFace Se pueden obtener los posibles valores desde la clase com.itextpdf.text.pdf.BaseFont\n\tValor por defecto = BaseFont.CP1252
     * @param embeddedTypeFace
     * @throws DocumentException
     * @throws IOException 
     */
    public static void addText(
        PdfStamper stamper, 
        String text, 
        int page, 
        int posX, 
        int posY, 
        int rotation, 
        int textSize,
        String typeFace,
        String encoderTypeFace,
        boolean embeddedTypeFace
    ) throws DocumentException, IOException {
        
        if (typeFace == null) typeFace = BaseFont.TIMES_ROMAN;
        if (encoderTypeFace == null) encoderTypeFace = BaseFont.CP1252;
        
        //OJO... Se debe validar valor de pagina
        PdfContentByte cb = stamper.getOverContent(page);
        cb.beginText();
        BaseFont bf = BaseFont.createFont(typeFace, encoderTypeFace, embeddedTypeFace);
        cb.setFontAndSize(bf, textSize);
        cb.showTextAligned(PdfContentByte.ALIGN_LEFT, text, posX, posY, rotation);
        cb.endText();
    }
    
    public static void addImage(
        PdfStamper stamper, 
        Image staticImage, 
        int page, 
        float width, 
        float height, 
        int posX, 
        int posY
    ) throws DocumentException  {
        //OJO... Se debe validar valor de pagina
        PdfContentByte cb = stamper.getOverContent(page);
        cb.addImage(staticImage, width, 0, 0, height, posX, posY);
    }
    ////////////////////////////////////////////////////////////////////////////
    
    /////////////////////////// Firma de PDF ///////////////////////////////////
    /**
     * Genera un objeto PdfStamper para iniciar el proceso de firma electronica.
     * 
     * @param pdfIn
     * @param pdfSigned
     * @return
     * @throws com.itextpdf.text.DocumentException
     * @throws IOException 
     */
    public static PdfStamper generateSignStamper(
        PdfReader pdfIn, 
        ByteArrayOutputStream pdfSigned
    ) throws DocumentException, IOException {
        //OJO... Implementar lo siguiente
        //En caso de ser un pdf muy grande, se debe utilizar un archivo temporal en disco para evitar OutOfMemoryExceptions.
        //PdfStamper pdfStamper = PdfStamper.createSignature(pdfIn, pdfFirmado, '\0', new File(rutaTemporal), true);
        AcroFields acroFields = pdfIn.getAcroFields();
        List<String> signatures = acroFields.getSignatureNames();
        if(signatures.isEmpty()) {
            return PdfStamper.createSignature(pdfIn, pdfSigned, '\0');
        } else {
            return PdfStamper.createSignature(pdfIn, pdfSigned, '\0', null, true);
        }
    }
    
    /**
     * Crear y configurar apariencia y propiedades de la firma
     * 
     * @param pdfStamper
     * @param certificate
     * @param readPass
     * @param writePass
     * @param reason
     * @param location
     * @param contact
     * @param signDate
     * @param noModify
     * @param visible
     * @param page
     * @param bytesImage
     * @param imgP1X
     * @param imgP1Y
     * @param imgP2X
     * @param imgP2Y
     * @param imgRotation
     * @return
     * @throws DocumentException
     * @throws PDFOperadorException
     * @throws BadElementException
     * @throws MalformedURLException
     * @throws IOException 
     */
    public static PdfSignatureAppearance initSignatureAppearance(
        PdfStamper pdfStamper, 
        X509Certificate certificate, 
        String readPass, 
        String writePass, 
        String reason, 
        String location, 
        String contact, 
        Date signDate, 
        boolean noModify, 
        boolean visible, 
        int page,
        byte[] bytesImage, 
        float imgP1X, 
        float imgP1Y, 
        float imgP2X, 
        float imgP2Y, 
        int imgRotation
    ) throws DocumentException, 
             PDFOperadorException, 
             BadElementException, 
             MalformedURLException, 
             IOException 
    {
        
        PdfSignatureAppearance signAppearance = pdfStamper.getSignatureAppearance();
        signAppearance.setCertificate(certificate);
        if (readPass != null) {
            pdfStamper.setEncryption(
                true, 
                readPass, 
                writePass, 
                    PdfWriter.ALLOW_PRINTING | 
                    PdfWriter.ALLOW_COPY | 
                    PdfWriter.ALLOW_SCREENREADERS | 
                    PdfWriter.ALLOW_DEGRADED_PRINTING
            );
            pdfStamper.setFormFlattening(false);
        }
        
        if (reason != null) signAppearance.setReason(reason);
        if (location != null) signAppearance.setLocation(location);
        if (contact != null) signAppearance.setContact(contact);
        if (signDate != null) {
            Calendar cal = Calendar.getInstance();
            cal.setTime(signDate);
            signAppearance.setSignDate(cal);
        } else {
            throw new PDFOperadorException(PDFOperadorException.ERROR_PDF_SIGN_DATE_NULL);
        }
        
        if (visible) {
            if(bytesImage!=null) signAppearance.setImage(Image.getInstance(bytesImage));
            try {
                String msj = I18n.get(
                        I18n.I_PDF_SIGN_LABEL_CONTENT,
                        CertificateHelper.getCN(certificate),
                        signAppearance.getReason(),
                        signAppearance.getLocation(),
                        DateHelper.dateToString(signDate)
                );
                signAppearance.setLayer2Text(msj);
            } catch (CertificateHelperException | DateHelperException ex) {
                //Do Nothing
            }
            signAppearance.setVisibleSignature(
                new Rectangle(imgP1X, imgP1Y, imgP2X, imgP2Y, imgRotation),
                page
            );
        }
        if (noModify)
            signAppearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        else
            signAppearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        
        return signAppearance;
    }
    
    /**
     * Generar archivo PDF firmado.
     * @param pdfIn
     * @param key
     * @param certificate
     * @param readPass
     * @param writePass
     * @param reason
     * @param location
     * @param contact
     * @param signDate
     * @param signAlg
     * @param noModify
     * @param visible
     * @param page
     * @param imgInBytes
     * @param imgP1X
     * @param imgP1Y
     * @param imgP2X
     * @param imgP2Y
     * @param imgRotation
     * @param cryptographyProvider
     * @return
     * @throws PDFOperadorException 
     */
    public static byte[] signLocalPDF(
        PdfReader pdfIn,
        PrivateKey key, 
        X509Certificate certificate, 
        String readPass, 
        String writePass, 
        String reason, 
        String location, 
        String contact, 
        Date signDate, 
        String signAlg, 
        boolean noModify, 
        boolean visible, 
        int page,
        byte[] imgInBytes, 
        float imgP1X, 
        float imgP1Y, 
        float imgP2X, 
        float imgP2Y, 
        int imgRotation,
        Provider cryptographyProvider
    )  throws PDFOperadorException {
        
        try {
            AlgorithmsHelper.isSupportedSignAlg(signAlg);
            
            ByteArrayOutputStream signedPDF = new ByteArrayOutputStream();
            PdfStamper pdfStamper = generateSignStamper(pdfIn, signedPDF);
            
            //Crear y configurar apariencia y propiedades de la firma
            PdfSignatureAppearance signAppearance = initSignatureAppearance(
                pdfStamper, 
                certificate, 
                readPass, 
                writePass, 
                reason, 
                location, 
                contact, 
                signDate, 
                noModify, 
                visible, 
                page, 
                imgInBytes, 
                imgP1X, 
                imgP1Y, 
                imgP2X, 
                imgP2Y, 
                imgRotation
            );
            
            //Preparar parámetros finales para firma
                cryptographyProvider = ProviderHelper.getRegCryptographyProviderOrDefault(cryptographyProvider);
            
                ExternalSignature es = 
                    new PrivateKeySignature(
                        key, 
                        AlgorithmsHelper.getHashAlgFromSignAlg(signAlg), 
                        cryptographyProvider.getName()
                );
                
                ExternalDigest digest = new BouncyCastleDigest();
                X509Certificate[] certs = new X509Certificate[1];
                certs[0] = certificate;
            
            //Procesar firma
            MakeSignature.signDetached(
                signAppearance, 
                digest, 
                es, 
                certs, 
                null, 
                null, 
                null, 
                0, 
                CryptoStandard.CMS
            );
            
            //Return
            return signedPDF.toByteArray();
        } catch (ProviderException ex) {
            throw new PDFOperadorException(new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE));
            
        } catch (DocumentException | 
                 IOException | 
                 IllegalArgumentException | 
                 GeneralSecurityException ex) {
            throw new PDFOperadorException(ex);
        }
    }
    
    public static byte[] preProcessPDFSign(
        PdfReader pdfIn,
        X509Certificate certificate, 
        String readPass, 
        String writePass, 
        String reason, 
        String location, 
        String contact, 
        Date signDate, 
        String signAlg, 
        boolean noModify, 
        boolean visible, 
        int page,
        byte[] imgInBytes, 
        float imgP1X, 
        float imgP1Y, 
        float imgP2X, 
        float imgP2Y, 
        int imgRotation,
        Provider cryptographyProvider
    ) throws PDFOperadorException {
        
        try {
            AlgorithmsHelper.isSupportedSignAlg(signAlg);
            
            ByteArrayOutputStream signedPDF = new ByteArrayOutputStream();
            PdfStamper pdfStamper = PDFOperator.generateSignStamper(pdfIn, signedPDF);
            
            //Crear y configurar apariencia y propiedades de la firma
            PdfSignatureAppearance signAppearance = PDFOperator.initSignatureAppearance(
                pdfStamper, 
                certificate, 
                readPass, 
                writePass, 
                reason, 
                location, 
                contact, 
                signDate, 
                noModify, 
                visible, 
                page, 
                imgInBytes, 
                imgP1X, 
                imgP1Y, 
                imgP2X, 
                imgP2Y, 
                imgRotation
            );
            
            //PreClose de propiedadesFirma
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
                dic.setReason(signAppearance.getReason());
                dic.setLocation(signAppearance.getLocation());
                dic.setContact(signAppearance.getContact());
                dic.setDate(new PdfDate(signAppearance.getSignDate()));
            signAppearance.setCryptoDictionary(dic);
            HashMap<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, 8192 * 2 + 2);
            signAppearance.preClose(exc);
            
            //Carcular Hash
            ExternalDigest externalDigest = new ExternalDigest() {
                @Override
                public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
                    return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
                }
            };
            
            InputStream data = signAppearance.getRangeStream();
            byte[] hash = DigestAlgorithms.digest(
                data, 
                externalDigest.getMessageDigest(AlgorithmsHelper.getHashAlgFromSignAlg(signAlg))
            );
            
            //Preprocesar Firma
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = certificate;
            ExternalDigest externalDigestClient = new ExternalDigest() {
                @Override
                public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
                    return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
                }
            };
            PdfPKCS7 pdfPKCS7Signer = new PdfPKCS7(
                null, 
                certs, 
                AlgorithmsHelper.getHashAlgFromSignAlg(signAlg), 
                null, 
                externalDigestClient, 
                false
            );
            Calendar cal = Calendar.getInstance();
            cal.setTime(signDate);
            byte[] firmaPreproc = 
                pdfPKCS7Signer.getAuthenticatedAttributeBytes(
                    hash, 
                    cal, 
                    null, 
                    null, 
                    CryptoStandard.CMS
            );
            
            //Procedimientos finales
            pdfStamper.close();
            signedPDF = null;
            System.gc();
            
            return firmaPreproc;
            
        } catch (DocumentException | 
                 IOException | 
                 IllegalArgumentException | 
                 GeneralSecurityException ex) {
            throw new PDFOperadorException(ex);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    
    ////////////////////////// Cifrado de PDF //////////////////////////////////
    public static byte[] encryptPDF(
        PdfReader pdfIn,
        String readPass, 
        String writePass
    ) throws PDFOperadorException {
        try {
            ByteArrayOutputStream signedPDF = new ByteArrayOutputStream();

            PdfStamper stamper = new PdfStamper(pdfIn, signedPDF);
            stamper.setEncryption(
                readPass.getBytes(), 
                writePass.getBytes(),
                PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_128 | PdfWriter.DO_NOT_ENCRYPT_METADATA
            );
            stamper.close();
            
            //Return
            return signedPDF.toByteArray();
            
        } catch (DocumentException | 
                 IOException | 
                 IllegalArgumentException ex) {
            throw new PDFOperadorException(ex);
        }
    }
    
    public static byte[] dencryptPDF(
        PdfReader pdfIn
    ) throws PDFOperadorException {
        try {
            ByteArrayOutputStream signedPDF = new ByteArrayOutputStream();

            PdfStamper stamper = new PdfStamper(pdfIn, signedPDF);
            stamper.close();
            
            //Return
            return signedPDF.toByteArray();
            
        } catch (DocumentException | 
                 IOException | 
                 IllegalArgumentException ex) {
            throw new PDFOperadorException(ex);
        }
    }    
    ////////////////////////////////////////////////////////////////////////////
}
