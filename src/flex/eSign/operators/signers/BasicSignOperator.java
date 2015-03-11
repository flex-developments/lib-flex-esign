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

package flex.eSign.operators.signers;

import flex.eSign.helpers.ProviderHelper;
import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.helpers.exceptions.AlgorithmsHelperException;
import flex.eSign.operators.exceptions.BasicSignOperatorException;
import flex.eSign.operators.exceptions.RSAOperatorException;
import flex.eSign.operators.HashOperator;
import flex.eSign.operators.RSAOperator;
import flex.helpers.SMimeCoderHelper;
import flex.helpers.exceptions.SMimeCoderHelperException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * BasicSignOperator
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public class BasicSignOperator {
    
    //////////////////////////// Procesos para Firma ///////////////////////////
    /**
     * Método que genera los bytes[] de una firma electrónica.
     *
     * @param data - Conjunto de Bytes[] de la data que se desea firmar.
     * @param privateKey - Llave privada que se desea utilizar para firmar electrónicamente la data.
     * @param signAlg - Algoritmos de resúmen y asimétrico que se utilizarán para la generación de la firma electrónica (Ejemp. SHA1withRSA, SHA256withRSA, etc.).
     * @param cryptographyProvider
     * @return Retorna un conjunto de Bytes[] correspondientes al resultado del proceso de firma electrónica.
     * @throws flex.eSign.operators.exceptions.BasicSignOperatorException
     */
    public static byte[] generateBasicSign(
        byte[] data, 
        PrivateKey privateKey, 
        String signAlg,
        Provider cryptographyProvider
    ) throws BasicSignOperatorException {
        
        try {
            AlgorithmsHelper.isSupportedSignAlg(signAlg);
            cryptographyProvider = ProviderHelper.getRegCryptographyProviderOrDefault(cryptographyProvider);
            
            Signature digitalSign = Signature.getInstance(signAlg);
            digitalSign.initSign(privateKey);
            digitalSign.update(data);
            return digitalSign.sign();
            
        } catch (ProviderException ex) {
            throw new BasicSignOperatorException(
                AlgorithmsHelperException.ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE + " <" + signAlg + ">"
            );
            
        } catch (SignatureException ex) {
            throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_SIGN_GENERATION_PROCESS);
            
        } catch (InvalidKeyException ex) {
            throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_PRIVATE_KEY_INVALID);
            
        } catch (NoSuchAlgorithmException ex) {
            throw new BasicSignOperatorException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        }
    }
    
    public static boolean verifyBasicSign(
        byte[] data, 
        byte[] sign, 
        X509Certificate certificate, 
        String signAlg,
        Provider cryptographyProvider
    ) throws BasicSignOperatorException {
        
        try {
            AlgorithmsHelper.isSupportedSignAlg(signAlg);
            ProviderHelper.getRegCryptographyProviderOrDefault(cryptographyProvider);
            
            if(isBasicSign(new String(sign))) {
                sign = decode(new String(sign));
            }
            
            Signature signature = Signature.getInstance(signAlg);
            signature.initVerify(certificate);
            signature.update(data);
            return signature.verify(sign);
        
        } catch (SMimeCoderHelperException ex) {
            throw new BasicSignOperatorException(ex);
            
        } catch (SignatureException ex) {
            if(ex.getMessage().compareTo("Signature encoding error") == 0)
                throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_SIGN_ENCODE + signAlg);
            
            throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_SIGN_VERIFICATION_PROCESS);
            
        } catch (InvalidKeyException ex) {
            throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_CETIFICATE_INVALID);
            
        } catch (NoSuchAlgorithmException ex) {
            throw new BasicSignOperatorException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        }
    }
    
    //Firma en 2 pasos----------------------------------------------------------
    public static byte[] preProcessBasicSign(
        byte[] data, 
        String signAlg
    ) throws BasicSignOperatorException {
        try {
            return HashOperator.getHash(data, AlgorithmsHelper.getHashAlgFromSignAlg(signAlg));
            
        } catch (NoSuchAlgorithmException ex) {
            throw new BasicSignOperatorException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
        }
    }
    
    public static byte[] endProcessBasicSign(
        byte[] hash, 
        PrivateKey privateKey, 
        String signAlg
    ) throws BasicSignOperatorException {
        try {
            switch(AlgorithmsHelper.getAsymetricAlgFromSignAlg(signAlg)) {
                case AlgorithmsHelper.ASYMETRIC_ALGORITHM_RSA: {
                    byte[] encodedHash = HashOperator.getHashDEREncode(
                        hash, 
                        AlgorithmsHelper.getHashAlgFromSignAlg(signAlg)
                    );
                    return RSAOperator.rsaEncrypt(encodedHash, privateKey);
                }
            }
            
            throw new BasicSignOperatorException(AlgorithmsHelperException.ERROR_UNKNOWN_ALGORITHMS);
            
        } catch (NoSuchAlgorithmException | IOException | RSAOperatorException ex) {
            throw new BasicSignOperatorException(ex);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    
    //////////////////////////// Procesos Adicionales //////////////////////////
    final private static String BEGIN_BASIC_SIGNATURE = "-----BEGIN BASIC SIGNATURE-----";
    final private static String END_BASIC_SIGNATURE   = "-----END BASIC SIGNATURE-----";
    
    public static String encode(byte[] signature) throws SMimeCoderHelperException {
        return BEGIN_BASIC_SIGNATURE +  
               "\n" + SMimeCoderHelper.getSMimeEncoded(signature) +
               "\n" + END_BASIC_SIGNATURE;
    }
    
    public static byte[] decode(String encodedSign) 
    throws BasicSignOperatorException, SMimeCoderHelperException {
        encodedSign = encodedSign.trim();
        
        if (isBasicSign(encodedSign)) {
            if(encodedSign.startsWith(BEGIN_BASIC_SIGNATURE))
                encodedSign = encodedSign.replace(BEGIN_BASIC_SIGNATURE, "");
        
            if(encodedSign.endsWith(END_BASIC_SIGNATURE))
                encodedSign = encodedSign.replace(END_BASIC_SIGNATURE, "");
        
        } else throw new BasicSignOperatorException(BasicSignOperatorException.ERROR_BASIC_SIGN_NOT_FORMAT);
        
        return SMimeCoderHelper.getSMimeDecoded(encodedSign);
    }
    
    public static boolean isBasicSign(String encodedSign) {
        encodedSign = encodedSign.trim();
        
        if(
            (encodedSign.startsWith(BEGIN_BASIC_SIGNATURE)) && 
            (encodedSign.endsWith(END_BASIC_SIGNATURE))
        )
            return true;
        else
            return false;
    }
    ////////////////////////////////////////////////////////////////////////////
}
