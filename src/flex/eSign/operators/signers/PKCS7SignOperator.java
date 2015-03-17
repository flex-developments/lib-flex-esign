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
import flex.eSign.helpers.ProviderHelper;
import flex.eSign.operators.exceptions.InvalidCertificateException;
import flex.eSign.operators.exceptions.PKCS7SignOperatorException;
import flex.helpers.SMimeCoderHelper;
import flex.helpers.exceptions.SMimeCoderHelperException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

/**
 * PKCS7SignOperator
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class PKCS7SignOperator {
    
    //////////////////////////// Procesos para Firma ///////////////////////////
    /**
     * Método para generar una firma electrónica PKCS#7
     * 
     * Para generar un CertStore o Repositorio de Certificados, se pueden emplear
     * las siguientes instrucciones:
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            ArrayList<java.security.cert.Certificate> certList = new ArrayList<java.security.cert.Certificate>();
            certList.add(cert);
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
     *
     * @param data - Bytes de la data a firmar.
     * @param privateKey - Clave privada del firmante.
     * @param certificate - Certificado electrónico del firmante.
     * @param signAlg
     * @param detached - Booleano para incluir o no la data en el paquete de la firma.
     * @param certificateEmbeded - Booleano para incluir o no el certificado del firmante.
     * @param cryptographyProvider
     * @return Los bytes de la firma generada.
     * @throws flex.eSign.operators.exceptions.PKCS7SignOperatorException
     */
    public static byte[] generatePKCS7Sign(
        byte[] data, 
        PrivateKey privateKey, 
        X509Certificate certificate, 
        String signAlg, 
        boolean detached, 
        boolean certificateEmbeded,
        Provider cryptographyProvider
    ) throws PKCS7SignOperatorException {
        
        try {
            AlgorithmsHelper.isSupportedSignAlg(signAlg);
            cryptographyProvider = ProviderHelper.getRegCryptographyProviderOrDefault(cryptographyProvider);
            
            CMSProcessableByteArray content = new CMSProcessableByteArray(data); //buffer
            
            CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();
            ContentSigner contentSigner = 
                new JcaContentSignerBuilder(signAlg).setProvider(
                    cryptographyProvider
                ).build(privateKey)
            ;
            
            if (certificateEmbeded){
                signGen.addSignerInfoGenerator(
                    new SignerInfoGeneratorBuilder(
                        new BcDigestCalculatorProvider()
                    ).build(contentSigner, new X509CertificateHolder(certificate.getEncoded()))
                );
                
            } else {
                signGen.addSignerInfoGenerator(
                    new SignerInfoGeneratorBuilder(
                        new BcDigestCalculatorProvider()
                    ).build(contentSigner, certificate.getPublicKey().getEncoded())
                );
            }
            
            //OJO... Agregar
            //generador.addCertificatesAndCRLs(certs);
            
            CMSSignedData signedData = signGen.generate(content, detached);
            return signedData.getEncoded();
            
        } catch(OperatorCreationException | 
                CertificateEncodingException | 
                CMSException | 
                IOException | 
                NoSuchAlgorithmException ex
        ) {
            throw new PKCS7SignOperatorException(ex);
        }
    }

    public static boolean verifyPKCS7Sign(
        byte[] pkcs7
    ) throws PKCS7SignOperatorException {
        
        try {
            CMSSignedData signature = new CMSSignedData(pkcs7);
            
            Store certStore = signature.getCertificates();
            SignerInformationStore signers = signature.getSignerInfos();
            
            SignerInformation signerInfo = (SignerInformation)signers.getSigners().iterator().next();
            Collection certCollection = certStore.getMatches(signerInfo.getSID());
            X509CertificateHolder signerCertificateHolder = (X509CertificateHolder)certCollection.iterator().next();
            
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificateHolder);
            
            //Verificacion de la firma
            return signerInfo.verify(verifier);
            
        } catch (CMSException e) {
            //Error en la firma
            return false;
            
        } catch(CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new PKCS7SignOperatorException(new InvalidCertificateException(null, ex));
            
        } catch(OperatorCreationException | CertificateException ex) {
            throw new PKCS7SignOperatorException(ex);
        }
    }

    public static boolean verifyPKCS7Sign(
        byte[] pkcs7,
        X509Certificate certificate
    ) throws PKCS7SignOperatorException {
        
        try {
            CMSSignedData signature = new CMSSignedData(pkcs7);
            SignerInformationStore signers = signature.getSignerInfos();
            SignerInformation signerInfo = (SignerInformation)signers.getSigners().iterator().next();
            
            X509CertificateHolder signerCertificateHolder = new X509CertificateHolder(certificate.getEncoded());
            
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificateHolder);
            
            //Verificacion de la firma
            return signerInfo.verify(verifier);
            
        } catch (CMSException e) {
            //Error en la firma
            return false;
            
        } catch(CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new PKCS7SignOperatorException(new InvalidCertificateException(null, ex));
            
        } catch(OperatorCreationException | CertificateException | IOException ex) {
            throw new PKCS7SignOperatorException(ex);
        }
    }
    
    /**
     * Verificar PKCS#7 detached.
     * 
     * @param data
     * @param pkcs7
     * @return 
     * @throws flex.eSign.operators.exceptions.PKCS7SignOperatorException 
     */
    public static boolean verifyPKCS7DetachedSign(
        byte[] data, 
        byte[] pkcs7
    ) throws PKCS7SignOperatorException {
        
        try {
            CMSProcessable content = new CMSProcessableByteArray(data);
            CMSSignedData signature = new CMSSignedData(content, pkcs7);

            Store certStore = signature.getCertificates();
            SignerInformationStore signers = signature.getSignerInfos();
            
            SignerInformation signerInfo = (SignerInformation)signers.getSigners().iterator().next();
            Collection certCollection = certStore.getMatches(signerInfo.getSID());
            X509CertificateHolder signerCertificateHolder = (X509CertificateHolder)certCollection.iterator().next();
            
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificateHolder);
            
            //Verificacion de la firma
            return signerInfo.verify(verifier);
            
        } catch (CMSException e) {
            //Error en la firma
            return false;
            
        } catch(CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new PKCS7SignOperatorException(new InvalidCertificateException(null, ex));
            
        } catch(OperatorCreationException | CertificateException ex) {
            throw new PKCS7SignOperatorException(ex);
        }
    }
    
    /**
     * Verificar PKCS#7 detached.
     * 
     * @param data
     * @param pkcs7
     * @param certificate
     * @return 
     * @throws flex.eSign.operators.exceptions.PKCS7SignOperatorException 
     */
    public static boolean verifyPKCS7DetachedSign(
        byte[] data, 
        byte[] pkcs7, 
        X509Certificate certificate
    ) throws PKCS7SignOperatorException {
        
        try {
            CMSProcessable content = new CMSProcessableByteArray(data);
            CMSSignedData signature = new CMSSignedData(content, pkcs7);
            SignerInformationStore signers = signature.getSignerInfos();
            SignerInformation signerInfo = (SignerInformation)signers.getSigners().iterator().next();
            
            X509CertificateHolder signerCertificateHolder = new X509CertificateHolder(certificate.getEncoded());
            
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificateHolder);
            
            //Verificacion de la firma
            return signerInfo.verify(verifier);
            
        } catch (CMSException e) {
            //Error en la firma
            return false;
            
        } catch(CertificateExpiredException | CertificateNotYetValidException ex) {
            throw new PKCS7SignOperatorException(new InvalidCertificateException(null, ex));
            
        } catch(OperatorCreationException | CertificateException | IOException ex) {
            throw new PKCS7SignOperatorException(ex);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    
    //////////////////////////// Procesos Adicionales //////////////////////////
    final private static String BEGIN_PKCS7  = "-----BEGIN PKCS7-----";
    final private static String END_PKCS7    = "-----END PKCS7-----";

    public static String encode(byte[] object) throws SMimeCoderHelperException {
        return BEGIN_PKCS7 + "\n" + 
               SMimeCoderHelper.getSMimeEncoded(object) +
               "\n" +END_PKCS7;
    }

    public static byte[] decode(String encodedSign)
    throws PKCS7SignOperatorException, SMimeCoderHelperException {
        encodedSign = encodedSign.trim();
        
        if(isPKCS7Sign(encodedSign)) {
            if(encodedSign.startsWith(BEGIN_PKCS7))
                encodedSign = encodedSign.replace(BEGIN_PKCS7, "");

            if(encodedSign.endsWith(END_PKCS7))
                encodedSign = encodedSign.replace(END_PKCS7, "");

        } else throw new PKCS7SignOperatorException(PKCS7SignOperatorException.ERROR_PKCS7_SIGN_NOT_FORMAT);
        
        return SMimeCoderHelper.getSMimeDecoded(encodedSign);
    }
    
    public static boolean isPKCS7Sign(String encodedSign) {
        encodedSign = encodedSign.trim();
        
        return (encodedSign.startsWith(BEGIN_PKCS7)) && (encodedSign.endsWith(END_PKCS7));
    }
    ////////////////////////////////////////////////////////////////////////////
}
