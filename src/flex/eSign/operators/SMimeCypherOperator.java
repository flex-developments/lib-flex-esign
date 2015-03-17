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

package flex.eSign.operators;

import flex.eSign.helpers.ProviderHelper;
import flex.eSign.operators.exceptions.SMimeCypherOperatorException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

/**
 * SMimeCypherOperator
 * Clase utilitaria que provee cifrado y decifrado asimetrico bajo estandar SMime.
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public final class SMimeCypherOperator {
    
    public static byte[] encryptData(
        byte[] data, 
        X509Certificate certificate
    ) throws IOException, SMimeCypherOperatorException {
        CMSEnvelopedData ed = null;
        try {
            CMSTypedData message = new CMSProcessableByteArray(data);
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            Provider provider = ProviderHelper.getRegBouncyCastleCryptographyProvider();
            
            edGen.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(certificate).setProvider(provider)
            );
            //OJO... Revisar el resto de los algoritmos de cifrado
            //ed = edGen.generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(provider).build());
            ed = edGen.generate(
                message, 
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(provider).build()
            );
            
        } catch (CertificateEncodingException | CMSException ex) {
            throw new SMimeCypherOperatorException(ex);
        }
        
        return ed.getEncoded();
    }
    
    /**
     * Descifrar datos.
     *
     * @param   decKey, clave privada del usuario.
     * @param   encData, datos cifrados.
     * @return  byte[] de datos descifrados o null si el descifrado falla.
     * @throws flex.eSign.operators.exceptions.SMimeCypherOperatorException
     */
    public static byte[] decryptData(PrivateKey decKey, byte[] encData) throws SMimeCypherOperatorException {
        byte[] retdata = null;
        try{
            CMSEnvelopedData ed = new CMSEnvelopedData(encData);
            RecipientInformationStore  recipients = ed.getRecipientInfos();

            Collection  c = recipients.getRecipients();
            Iterator    it = c.iterator();
            Provider provider = ProviderHelper.getRegBouncyCastleCryptographyProvider();
            
            if (it.hasNext()){
                RecipientInformation   recipient = (RecipientInformation)it.next();
                retdata = recipient.getContent(
                    new JceKeyTransEnvelopedRecipient(decKey).setProvider(provider)
                );
            }
            
        } catch(CMSException ex){
            throw new SMimeCypherOperatorException(ex);
        }

        return retdata;
    }
}
