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

package flex.eSign.test;

import com.itextpdf.text.pdf.PdfReader;
import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.operators.signers.PDFOperator;
import flex.helpers.FileHelper;
import flex.pkikeys.PKIKeys;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * PDFOperatorTest
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class PDFOperatorTest {
    
    public static void main(String[] args) {
        signLocalPDFTest();
//        encryptPDFTest();
//        dencryptPDFTest();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void signLocalPDFTest() {
        
        try {
            PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
            
            String rutaOrigen = TestsResources.resourcesPath + "prueba1.pdf";
            String rutaDestino = TestsResources.resourcesPath + "prueba2.pdf";
            byte[] imageInByte = FileHelper.getBytes(TestsResources.resourcesPath + "fondo_firma.png");
            PdfReader pdfIn = PDFOperator.getPdfReader(new File(rutaOrigen), null);
            //Date fechaFirma = new Date();
            Date fechaFirma = (new SimpleDateFormat("dd-M-yyyy hh:mm:ss").parse("10-10-2014 00:00:00"));
            
            byte[] pdfFirmado = PDFOperator.signLocalPDF(
                pdfIn, 
                clientKeys.getPrivateKey(), 
                clientKeys.getSignCertificate(), 
                null, 
                null, 
                "Razon", 
                "Location", 
                "user@dominio.com", 
                fechaFirma, 
                AlgorithmsHelper.SIGN_ALGORITHM_SHA512_RSA, 
                false, 
                true, 
                19, 
                imageInByte, 
                200, 
                200, 
                350, 
                250, 
                0,
                clientKeys.getRepositoryCryptographyProvider()
            );

            FileHelper.write(rutaDestino, pdfFirmado);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void encryptPDFTest() {
        
        try {
            String rutaOrigen = TestsResources.resourcesPath + "prueba1.pdf";
            String rutaDestino = TestsResources.resourcesPath + "prueba2.pdf";
            
            PdfReader pdfIn = PDFOperator.getPdfReader(new File(rutaOrigen), null);
            byte[] pdfResult = PDFOperator.encryptPDF(pdfIn, "read-pass", "write-pass");
            
            FileHelper.write(rutaDestino, pdfResult);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void dencryptPDFTest() {
        
        try {
            String rutaOrigen = TestsResources.resourcesPath + "prueba2.pdf";
            String rutaDestino = TestsResources.resourcesPath + "prueba3.pdf";
            
            PdfReader pdfIn = PDFOperator.getPdfReader(new File(rutaOrigen), "write-pass");
            byte[] pdfResult = PDFOperator.dencryptPDF(pdfIn);
            
            FileHelper.write(rutaDestino, pdfResult);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
