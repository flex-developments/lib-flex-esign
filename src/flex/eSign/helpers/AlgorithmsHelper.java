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

package flex.eSign.helpers;

import flex.eSign.helpers.exceptions.AlgorithmsHelperException;

/**
 * AlgorithmsHelper
 *
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @version 1.0
 */
public class AlgorithmsHelper {
    final public static String SIGN_ALGORITHM_SHA1_RSA = "SHA1withRSA";
    final public static String SIGN_ALGORITHM_SHA224_RSA = "SHA224withRSA";
    final public static String SIGN_ALGORITHM_SHA256_RSA = "SHA256withRSA";
    final public static String SIGN_ALGORITHM_SHA384_RSA = "SHA384withRSA";
    final public static String SIGN_ALGORITHM_SHA512_RSA = "SHA512withRSA";
    
    final public static String HASH_ALGORITHM_SHA1 = "SHA-1";
    final public static String HASH_ALGORITHM_SHA224 = "SHA-224";
    final public static String HASH_ALGORITHM_SHA256 = "SHA-256";
    final public static String HASH_ALGORITHM_SHA384 = "SHA-384";
    final public static String HASH_ALGORITHM_SHA512 = "SHA-512";
    
    final public static String ASYMETRIC_ALGORITHM_RSA = "RSA";
    
    /////////////////////////////// Asimetricos ////////////////////////////////
    public static boolean isSupportedSignAlg(String signAlg) throws AlgorithmsHelperException {
        if(
            (signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA1_RSA) != 0) &&
            (signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA224_RSA) != 0) &&
            (signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA256_RSA) != 0) &&
            (signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA384_RSA) != 0) &&
            (signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA512_RSA) != 0)
        ) {
            throw new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        } else {
            return true;
        }
    }
    
    public static String getAsymetricAlgFromSignAlg(String signAlg) throws AlgorithmsHelperException {
        if(
            (signAlg.compareTo(SIGN_ALGORITHM_SHA1_RSA) != 0) &&
            (signAlg.compareTo(SIGN_ALGORITHM_SHA224_RSA) != 0) &&
            (signAlg.compareTo(SIGN_ALGORITHM_SHA256_RSA) != 0) &&
            (signAlg.compareTo(SIGN_ALGORITHM_SHA384_RSA) != 0) &&
            (signAlg.compareTo(SIGN_ALGORITHM_SHA512_RSA) != 0)
        ) {
            throw new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        } else {
            return ASYMETRIC_ALGORITHM_RSA;
        }
    }
    
    /////////////////////////////////// Hash ///////////////////////////////////
    public static boolean isSupportedHashAlg(String hashAlg) throws AlgorithmsHelperException {
        if(
            (hashAlg.compareToIgnoreCase(HASH_ALGORITHM_SHA1) != 0) &&
            (hashAlg.compareToIgnoreCase(HASH_ALGORITHM_SHA224) != 0) &&
            (hashAlg.compareToIgnoreCase(HASH_ALGORITHM_SHA256) != 0) &&
            (hashAlg.compareToIgnoreCase(HASH_ALGORITHM_SHA384) != 0) &&
            (hashAlg.compareToIgnoreCase(HASH_ALGORITHM_SHA256) != 0)
        ) {
            throw new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        } else {
            return true;
        }
    }
    
    public static String getHashAlgFromSignAlg(String signAlg) throws AlgorithmsHelperException {
        if(signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA1_RSA) == 0)
            return HASH_ALGORITHM_SHA1;
        
        if(signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA224_RSA) == 0)
            return HASH_ALGORITHM_SHA224;
        
        if(signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA256_RSA) == 0)
            return HASH_ALGORITHM_SHA256;
        
        if(signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA384_RSA) == 0)
            return HASH_ALGORITHM_SHA384;
        
        if(signAlg.compareToIgnoreCase(SIGN_ALGORITHM_SHA512_RSA) == 0)
            return HASH_ALGORITHM_SHA512;
        
        throw new AlgorithmsHelperException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
    }
}
