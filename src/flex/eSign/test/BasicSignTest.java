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

import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.operators.signers.BasicSignOperator;
import flex.pkikeys.PKIKeys;

/**
 * BasicSignTest
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class BasicSignTest {
    
    public static void main(String[] args) {
        signTwoPartsTest();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void signTwoPartsTest() {
        try {
            PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
            byte[] data = "test".getBytes();
            String signAlg = AlgorithmsHelper.SIGN_ALGORITHM_SHA512_RSA;
            
            byte[] hash = BasicSignOperator.preProcessBasicSign(data, signAlg);
            
            byte[] signature = BasicSignOperator.endProcessBasicSign(hash, clientKeys.getPrivateKey(), signAlg);
            
            boolean verify = BasicSignOperator.verifyBasicSign(
                data, 
                signature, 
                clientKeys.getSignCertificate(), 
                signAlg, 
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            String encodedSignature = BasicSignOperator.encode(signature);
            
            System.out.println(encodedSignature + "\nVerified? " + verify);
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
