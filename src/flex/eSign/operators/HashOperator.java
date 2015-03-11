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

package flex.eSign.operators;

import flex.helpers.HexCoderHelper;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

/**
 * HashOperator
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public final class HashOperator {
    
    public static byte[] getHash(byte[] data, String hashAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return md.digest(data);
    }
    
    public static String getHexCheckSum(byte[] data, String hashAlgorithm) throws NoSuchAlgorithmException {
        byte[] hash = getHash(data, hashAlgorithm);
        return HexCoderHelper.getStringHexEncoded(hash);
    }
    
    public static byte[] getHashDEREncode(byte[] hash, String hashAlgorithm) throws NoSuchAlgorithmException, IOException {
        DefaultDigestAlgorithmIdentifierFinder aux = new DefaultDigestAlgorithmIdentifierFinder();
        DigestInfo dInfo=new DigestInfo(aux.find(hashAlgorithm), hash);
        return dInfo.getEncoded();
    }
}
