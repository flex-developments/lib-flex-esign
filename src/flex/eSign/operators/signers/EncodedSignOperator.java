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

package flex.eSign.operators.signers;

import flex.eSign.i18n.I18n;
import flex.eSign.operators.exceptions.BasicSignOperatorException;
import flex.eSign.operators.exceptions.DatedSignOperatorException;
import flex.eSign.operators.exceptions.EncodedSignOperatorException;
import flex.eSign.operators.exceptions.PKCS7SignOperatorException;
import flex.helpers.HexCoderHelper;
import flex.helpers.exceptions.DateHelperException;
import flex.helpers.exceptions.SMimeCoderHelperException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * EncodedSignOperator
 * Clase que implementa la generación de firmas electrónicas en sus diferentes
 * estandares y cuyo resultado se codifica SMime/Base64.
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class EncodedSignOperator {
    final public static String ENCODED_SIGN_STANDARD_BASIC = "basica";
    final public static String ENCODED_SIGN_STANDARD_DATED = "fechada";
    final public static String ENCODED_SIGN_STANDARD_PKCS7 = "pkcs7";
    
    ///////////////////////////// Firma de Strings /////////////////////////////
    /**
        Ejemplo de verificación de firma electrónica de una cadena de texto con openssl:

         1.- Se escribe la cadena de texto en un documento data.txt
         2.- Se escribe la cadena del certificado electrónico en un documento certificado.txt
         3.- Se escribe la cadena de firma electrónica en un documento firma.txt sin 
        incluir las líneas del encabezado "-----BEGIN BASIC SIGNATURE-----" ni el
        pie de página "-----END BASIC SIGNATURE-----"

        //OJO... Finalizar la estructuración de un proceso que permita la verificacion
 
     * a través de openssl (PKCS#7 ya existe, se debe copiar aqui)
     * 
     *  4.- Ejecutar los siguientes comandos
     *      $ openssl base64 -d -in firma.txt -out firma-decoded.sig
     *  5.- 
     * 
     * 
     * @param signStandard
     * @param data
     * @param date
     * @param privateKey
     * @param certificate
     * @param signAlg
     * @param cryptographyProvider
     * 
     * @return
     * 
     * @throws EncodedSignOperatorException 
     */
    public static String generateSMimeEncodedSignOfString(
        String signStandard,
        byte[] data,
        Date date,
        PrivateKey privateKey,
        X509Certificate certificate,
        String signAlg,
        Provider cryptographyProvider
    ) throws EncodedSignOperatorException {
        try {
            switch (signStandard) {
                case ENCODED_SIGN_STANDARD_BASIC: {
                    byte[] basicSign = BasicSignOperator.generateBasicSign(data, privateKey, signAlg, cryptographyProvider);
                    return BasicSignOperator.encode(basicSign);
                }
                
                case ENCODED_SIGN_STANDARD_DATED: {
                    byte[] datedSign = DatedSignOperator.genDatedSign(data, date, privateKey, signAlg, cryptographyProvider);
                    return DatedSignOperator.encode(datedSign);
                }
                    
                case ENCODED_SIGN_STANDARD_PKCS7: {
                    byte[] pkcs7Sign = PKCS7SignOperator.generatePKCS7Sign(data, privateKey, certificate, signAlg, false, false, cryptographyProvider);
                    return PKCS7SignOperator.encode(pkcs7Sign);
                }

                default: {
                    throw new EncodedSignOperatorException(I18n.get(I18n.M_ERROR_SIGN_STANDARD_NOT_SUPPORTED, signStandard));
                }
            }
            
        } catch (BasicSignOperatorException | DatedSignOperatorException | 
                 SMimeCoderHelperException | 
                 DateHelperException |
                 PKCS7SignOperatorException ex
        ) {
            throw new EncodedSignOperatorException(ex);
        }
    }
    
    /**
     * 
     * @param data
     * @param dateSign
     * @param certificate
     * @param encodedSign
     * @param signAlg
     * @param cryptographyProvider
     * 
     * @return
     * 
     * @throws EncodedSignOperatorException 
     */
    public static boolean verifySMimeEncodedSignOfString(
        byte[] data,
        Date dateSign, 
        String encodedSign, 
        X509Certificate certificate, 
        String signAlg,
        Provider cryptographyProvider
    ) throws EncodedSignOperatorException {
        try {
            if(BasicSignOperator.isBasicSign(encodedSign)) {
                byte[] sign = BasicSignOperator.decode(encodedSign);
                
                return BasicSignOperator.verifyBasicSign(data, sign, certificate, signAlg, cryptographyProvider);
                
            } else if(PKCS7SignOperator.isPKCS7Sign(encodedSign)) {
                byte[] pkcs7 = PKCS7SignOperator.decode(encodedSign);
                return PKCS7SignOperator.verifyPKCS7DetachedSign(data, pkcs7, certificate);
                
            } else if(DatedSignOperator.isDatedSign(encodedSign)) {
                if(dateSign == null) 
                    throw new DateHelperException(DateHelperException.ERROR_STRING_TO_DATE_NULL); 
                    
                byte[] sign = DatedSignOperator.decode(encodedSign);
                return DatedSignOperator.verifyDatedSign(data, dateSign, sign, certificate, signAlg, cryptographyProvider);
                
            } else {
                throw new EncodedSignOperatorException(I18n.get(I18n.M_ERROR_SIGN_STANDARD_NOT_SUPPORTED, ""));
            }
            
        } catch (BasicSignOperatorException | PKCS7SignOperatorException | 
                 SMimeCoderHelperException | 
                 DateHelperException | 
                 DatedSignOperatorException ex
        ) {
            throw new EncodedSignOperatorException(ex);
        }
    }
    
    ///////////////////////////// Firma en 2 pasos /////////////////////////////
    //Paso 1.- Generar hash de la data[]
    public static String getHexHashToSign(
        String signStandard,
        byte[] data, 
        Date date, 
        String signAlg
    ) throws EncodedSignOperatorException {
         try {
            switch (signStandard) {
                case ENCODED_SIGN_STANDARD_BASIC: {
                    byte[] basicSign = BasicSignOperator.preProcessBasicSign(data, signAlg);
                    return HexCoderHelper.getStringHexEncoded(basicSign);
                }
                
                case ENCODED_SIGN_STANDARD_DATED: {
                    byte[] datedSign = DatedSignOperator.getHexHashToSign(data, date, signAlg);
                    return HexCoderHelper.getStringHexEncoded(datedSign);
                }
                    
                case ENCODED_SIGN_STANDARD_PKCS7: {
                    //OJO... Falta
                    throw new EncodedSignOperatorException("Not supported yeat");
                }

                default: {
                    throw new EncodedSignOperatorException(I18n.get(I18n.M_ERROR_SIGN_STANDARD_NOT_SUPPORTED, signStandard));
                }
            }
            
        } catch (BasicSignOperatorException | DatedSignOperatorException ex) {
            throw new EncodedSignOperatorException(ex);
        }
    }
    
    //Paso 2.- Cifrar Asimetricamente el Hash de la data[]
    public static String endSMimeSignFromHexHash(
        String signStandard,
        String hexEncodedHash,
        PrivateKey privateKey,
        String signAlg
    ) throws EncodedSignOperatorException {
        try {
            byte[] hash = HexCoderHelper.getByteArrayHexDecoded(hexEncodedHash);
            
            switch (signStandard) {
                case ENCODED_SIGN_STANDARD_BASIC: {
                    byte[] basicSign = BasicSignOperator.endProcessBasicSign(hash, privateKey, signAlg);
                    return BasicSignOperator.encode(basicSign);
                }
                
                case ENCODED_SIGN_STANDARD_DATED: {
                    byte[] datedSign = DatedSignOperator.endSMimeSignFromHexHash(hash, privateKey, signAlg);
                    return DatedSignOperator.encode(datedSign);
                }
                    
                case ENCODED_SIGN_STANDARD_PKCS7: {
                    //OJO... Falta
                    throw new EncodedSignOperatorException("Building...");
                }

                default: {
                    throw new EncodedSignOperatorException(I18n.get(I18n.M_ERROR_SIGN_STANDARD_NOT_SUPPORTED, signStandard));
                }
            }
            
        } catch (BasicSignOperatorException | 
                 SMimeCoderHelperException | 
                 DatedSignOperatorException ex
        ) {
            throw new EncodedSignOperatorException(ex);
        }
    }
}
