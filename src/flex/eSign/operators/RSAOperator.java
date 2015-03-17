/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments en gmail
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - fdmarchena2003@hotmail.com | flopez en suscerte gob ve
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

package flex.eSign.operators;

import flex.eSign.helpers.exceptions.AlgorithmsHelperException;
import flex.eSign.operators.exceptions.RSAOperatorException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSAOperator
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class RSAOperator {
    
    public static byte[] rsaEncrypt(byte[] data, Key key) throws RSAOperatorException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
            
        } catch (NoSuchAlgorithmException ex) {
            throw new RSAOperatorException(new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS));
            
        } catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new RSAOperatorException(ex);
        }
    }
    
    public static byte[] rsaDecrypt(byte[] data, Key key) throws RSAOperatorException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
            
        } catch (NoSuchAlgorithmException ex) {
            throw new RSAOperatorException(new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS));
            
        } catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new RSAOperatorException(ex);
        }
    }
}
