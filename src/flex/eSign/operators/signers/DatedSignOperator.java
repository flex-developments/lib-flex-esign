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

package flex.eSign.operators.signers;

import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.i18n.I18n;
import flex.eSign.operators.exceptions.BasicSignOperatorException;
import flex.eSign.operators.exceptions.DatedSignOperatorException;
import flex.eSign.operators.exceptions.RSAOperatorException;
import flex.helpers.DateHelper;
import flex.eSign.operators.HashOperator;
import flex.eSign.operators.RSAOperator;
import flex.helpers.SMimeCoderHelper;
import flex.helpers.exceptions.DateHelperException;
import flex.helpers.exceptions.SMimeCoderHelperException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * DatedSignOperator
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class DatedSignOperator {
    
    //////////////////////////// Procesos para Firma ///////////////////////////
    public static byte[] genDatedSign(
        byte[] data, 
        Date date,
        PrivateKey privateKey, 
        String signAlg,
        Provider cryptographyProvider
    ) throws DatedSignOperatorException, DateHelperException {
        
        try {
            return BasicSignOperator.generateBasicSign(addDate(data, date, signAlg), privateKey, signAlg, cryptographyProvider);
            
        } catch (BasicSignOperatorException | NoSuchAlgorithmException ex) {
            throw new DatedSignOperatorException(ex);
            
        } catch (IOException ex) {
            throw new DatedSignOperatorException(DatedSignOperatorException.ERROR_ADD_DATE);
        }
    }

    public static boolean verifyDatedSign(
        byte[] data,
        Date date, 
        byte[] sign,
        X509Certificate certificate,
        String signAlg,
        Provider cryptographyProvider
    ) throws DatedSignOperatorException, DateHelperException {
        try {
            if(isDatedSign(new String(sign)))
                sign = decode(new String(sign));
            
            return BasicSignOperator.verifyBasicSign(addDate(data, date, signAlg), sign, certificate, signAlg, cryptographyProvider);
            
        } catch (SMimeCoderHelperException | BasicSignOperatorException | NoSuchAlgorithmException ex) {
            throw new DatedSignOperatorException(ex);
            
        } catch (IOException ex) {
            throw new DatedSignOperatorException(DatedSignOperatorException.ERROR_ADD_DATE);
        }
    }
    
    public static byte[] addDate(
        byte[] data, 
        Date date, 
        String signAlg
    ) throws IOException, 
             DateHelperException, 
             NoSuchAlgorithmException 
    {
        byte[] dataHash = HashOperator.getHash(
            data, 
            AlgorithmsHelper.getHashAlgFromSignAlg(signAlg)
        );
        byte[] bytesFecha = DateHelper.dateToString(date).getBytes();
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(dataHash);
        outputStream.write(bytesFecha);

        return outputStream.toByteArray( );
    }
    
    //Firma en 2 pasos----------------------------------------------------------
    public static byte[] getHexHashToSign(
        byte[] data, 
        Date date, 
        String signAlg
    ) throws DatedSignOperatorException {
        try {
            return HashOperator.getHash(
                addDate(data, date, signAlg), 
                AlgorithmsHelper.getHashAlgFromSignAlg(signAlg)
            );
            
        } catch (NoSuchAlgorithmException | 
                 IOException | 
                 DateHelperException ex
        ) {
            throw new DatedSignOperatorException(I18n.M_ERROR_UNKNOWN_ALGORITHMS);
        }
    }
    
    public static byte[] endSMimeSignFromHexHash(
        byte[] hash, 
        PrivateKey privateKey, 
        String signAlg
    ) throws DatedSignOperatorException {
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
            
            throw new DatedSignOperatorException(I18n.M_ERROR_UNKNOWN_ALGORITHMS);
            
        } catch (NoSuchAlgorithmException | IOException | RSAOperatorException ex) {
            throw new DatedSignOperatorException(ex);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    
    //////////////////////////// Procesos Adicionales //////////////////////////
    final private static String BEGIN_DATED_SIGNATURE = "-----BEGIN DATED SIGNATURE-----";
    final private static String END_DATED_SIGNATURE   = "-----END DATED SIGNATURE-----";
    
    public static String encode(byte[] sign) throws SMimeCoderHelperException {
        return BEGIN_DATED_SIGNATURE +  
               "\n" + SMimeCoderHelper.getSMimeEncoded(sign) +
               "\n" + END_DATED_SIGNATURE;
    }
    
    public static byte[] decode(String encodedSign) 
    throws DatedSignOperatorException, SMimeCoderHelperException {
        encodedSign = encodedSign.trim();
        
        if (isDatedSign(encodedSign)) {
            if(encodedSign.startsWith(BEGIN_DATED_SIGNATURE))
                encodedSign = encodedSign.replace(BEGIN_DATED_SIGNATURE, "");
        
            if(encodedSign.endsWith(END_DATED_SIGNATURE))
                encodedSign = encodedSign.replace(END_DATED_SIGNATURE, "");
        
        } else throw new DatedSignOperatorException(DatedSignOperatorException.ERROR_DATED_SIGN_NOT_FORMAT);
        
        return SMimeCoderHelper.getSMimeDecoded(encodedSign);
    }
    
    public static boolean isDatedSign(String encodedSign) {
        encodedSign = encodedSign.trim();
        
        return (encodedSign.startsWith(BEGIN_DATED_SIGNATURE)) && 
                (encodedSign.endsWith(END_DATED_SIGNATURE));
    }
    ////////////////////////////////////////////////////////////////////////////
}
