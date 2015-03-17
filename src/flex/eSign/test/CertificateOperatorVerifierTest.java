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

import flex.eSign.helpers.exceptions.CertificateHelperException;
import flex.eSign.operators.CertificateVerifierOperator;
import flex.eSign.operators.components.CertificateVerifierConfig;
import flex.eSign.operators.components.CertificateVerifierOperatorResults;
import flex.pkikeys.PKIKeys;

/**
 * CertificateOperatorVerifierTest
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class CertificateOperatorVerifierTest {
    
    public static void main(String[] args) throws Exception {
        certificateVerifierTest();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void certificateVerifierTest() throws CertificateHelperException, Exception {
        PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
        
        CertificateVerifierConfig vcConfig =
            CertificateVerifierConfig.getInstanceToNewSign(
                clientKeys.getSignCertificate(), 
                TestsResources.getAuthorities(), 
                null, 
                TestsResources.getNTPServers(),
                true
        );
        
        vcConfig.setTryDownloadCRL(false);
        vcConfig.setVerifyWithOCSP(true);
        
        CertificateVerifierOperatorResults results = 
            CertificateVerifierOperator.verifyToNewSignature(vcConfig);
        
        System.out.println("Authorized?:\n" + results.isAutorized());
        System.out.println("Details:\n" + results.getDetails());
        
        System.exit(0);
    }
}
