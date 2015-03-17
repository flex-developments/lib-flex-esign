/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com | flopez@suscerte.gob.ve
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

import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.operators.signers.DatedSignOperator;
import flex.pkikeys.PKIKeys;
import java.util.Date;

/**
 * BasicSignTest
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @version 1.0
 */
public class DatedSignTest {
    
    public static void main(String[] args) {
        signTest();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void signTest() {
        try {
            PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
            byte[] data = "test".getBytes();
            Date date = new Date();
            String signAlg = AlgorithmsHelper.SIGN_ALGORITHM_SHA256_RSA;
            
            byte[] signature = DatedSignOperator.genDatedSign(
                data, 
                date, 
                clientKeys.getPrivateKey(), 
                signAlg,
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            boolean verify = DatedSignOperator.verifyDatedSign(
                data, 
                date, 
                signature, 
                clientKeys.getSignCertificate(), 
                signAlg,
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            String encodedSignature = DatedSignOperator.encode(signature);
            System.out.println(encodedSignature + "\nVerified? " + verify);
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
