/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments en gmail
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments en gmail | flopez en suscerte gob ve
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

import flex.eSign.helpers.CertificateHelper;
import flex.eSign.helpers.exceptions.CertificateHelperException;
import java.security.cert.X509Certificate;

/**
 * CertificateHelperTest
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class CertificateHelperTest {
    
    public static void main(String[] args) throws Exception {
        certificateDecoderTest();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void certificateDecoderTest() throws CertificateHelperException {
        String cert = "-----BEGIN CERTIFICATE-----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-----END CERTIFICATE-----";
        X509Certificate certificate = CertificateHelper.decode(cert);
        System.out.println(certificate.getSubjectDN());
    }
}
