/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com | flopez@suscerte.gob.ve
 * Ing. Yessica De Ascencao - yessicadeascencao@gmail.com | ydeascencao@suscerte.gob.ve
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
import flex.eSign.operators.signers.EncodedSignOperator;
import flex.pkikeys.PKIKeys;
import java.util.Date;

/**
 * EncodedSignOperatorTest
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public class EncodedSignOperatorTest {
    
    public static void main(String[] args) {
//        trySignString();
        trySignTwoParts();
        
        System.out.println("End!");
        System.exit(0);
    }
    
    private static void trySignString() {
        try {
            PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
            String data = "test";
            Date date = new Date();
            String signStandard = EncodedSignOperator.ENCODED_SIGN_STANDARD_BASIC;
            String signAlg = AlgorithmsHelper.SIGN_ALGORITHM_SHA512_RSA;
            
            String signature = EncodedSignOperator.generateSMimeEncodedSignOfString(
                signStandard, 
                data.getBytes(), 
                date, 
                clientKeys.getPrivateKey(), 
                clientKeys.getSignCertificate(), 
                signAlg,
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            boolean verify = EncodedSignOperator.verifySMimeEncodedSignOfString(
                data.getBytes(), 
                date, 
                signature, 
                clientKeys.getSignCertificate(), 
                signAlg,
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            System.out.println(signature + "\nVerified? " + verify);
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private static void trySignTwoParts() {
        try {
            PKIKeys clientKeys = TestsResources.getKeys(true, false, true);
            String data = "test";
            Date date = new Date();
            String signStandard = EncodedSignOperator.ENCODED_SIGN_STANDARD_BASIC;
            String signAlg = AlgorithmsHelper.SIGN_ALGORITHM_SHA512_RSA;
            
            String hash = EncodedSignOperator.getHexHashToSign(
                signStandard, 
                data.getBytes(), 
                date, 
                signAlg
            );
            
            System.out.println("");
            System.out.println(hash);
            System.out.println("");
            
            String signature = EncodedSignOperator.endSMimeSignFromHexHash(
                signStandard, 
                hash, 
                clientKeys.getPrivateKey(), 
                signAlg
            );
            
            boolean verify = EncodedSignOperator.verifySMimeEncodedSignOfString(
                data.getBytes(), 
                date, 
                signature, 
                clientKeys.getSignCertificate(), 
                signAlg,
                clientKeys.getRepositoryCryptographyProvider()
            );
            
            System.out.println(signature + "\nVerified? " + verify);
            
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
