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

package flex.eSign.helpers;

import flex.eSign.helpers.exceptions.CertificateHelperException;
import flex.eSign.helpers.exceptions.ANS1EncodableHelperException;
import flex.eSign.i18n.I18n;
import flex.eSign.operators.exceptions.TrustPathException;
import flex.helpers.SMimeCoderHelper;
import flex.helpers.exceptions.SMimeCoderHelperException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * CertificateHelper
 *
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public class CertificateHelper {
    public final static String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public final static String END_CERTIFICATE = "-----END CERTIFICATE-----";
    
    public static List<X509Certificate> loadPEMCertificate(InputStream inStream) 
    throws CertificateHelperException {
        List<X509Certificate> lista = new ArrayList<>();
        
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<Certificate> certs =
                    (Collection<Certificate>) cf.generateCertificates(inStream);
            
            for(Certificate cert: certs) lista.add((X509Certificate) cert);
                    
            return lista;
            
        } catch (CertificateException ex) {
            throw new CertificateHelperException(ex);
        }
    }
    
    public static String encode(X509Certificate certificate) throws CertificateHelperException {
        try {
            return BEGIN_CERTIFICATE + 
                   "\n" + SMimeCoderHelper.getSMimeEncoded(certificate.getEncoded()) +
                   "\n" + END_CERTIFICATE;
            
        } catch (SMimeCoderHelperException | CertificateEncodingException ex) {
            throw new CertificateHelperException(ex);
            
        }
    }
    
    public static X509Certificate decode(String certificate) throws CertificateHelperException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate)cf.generateCertificate(
                    new ByteArrayInputStream(certificate.getBytes())
            );
            
        } catch (CertificateException ex) {
            throw new CertificateHelperException(ex);
        }
    }
    
    public static String getCN(X509Certificate certificate) throws CertificateHelperException {
        try {
            X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return IETFUtils.valueToString(cn.getFirst().getValue());
            
        } catch (CertificateEncodingException ex) {
            throw new CertificateHelperException(ex);
        }
    }
    
    /**
     * Filtrar autoridades y construir cadena de un certificado.
     * @param certificate
     * @param authorities
     * @return
     * @throws TrustPathException 
     */
    public static List<X509Certificate> getAuthorities(
        X509Certificate certificate, 
        List<X509Certificate> authorities
    ) throws TrustPathException {
        List<X509Certificate> result = new ArrayList<>();
        if(getIssuer(certificate, authorities) == certificate) {
            result.add(certificate);
            
        } else {
            X509Certificate issuer = getIssuer(certificate, authorities);
            for(X509Certificate superior : getAuthorities(issuer,authorities)) {
                if(!result.contains(superior)) result.add(superior);
            }
            result.add(issuer);
        }
        return result;
    }
    
    public static X509Certificate getIssuer(
        X509Certificate certificate, 
        List<X509Certificate> authorities
    ) throws TrustPathException {
        if(certificate == null || authorities==null || authorities.isEmpty()) 
            throw new TrustPathException(TrustPathException.NOT_AUTHORITIES);
        
        if (
            !(
                certificate.getIssuerX500Principal().getName(X500Principal.RFC2253).compareTo(
                        certificate.getSubjectX500Principal().getName(X500Principal.RFC2253)
                    ) == 0
            )
        ) {
            for (X509Certificate certTrusted : authorities) {
                try {
                    certificate.verify(certTrusted.getPublicKey());
                    
                    if(
                        certificate.getIssuerX500Principal().getName(X500Principal.RFC2253).compareTo(
                                certTrusted.getSubjectX500Principal().getName(X500Principal.RFC2253)
                            ) == 0
                    )
                        return (certTrusted);

                } catch (CertificateException | 
                         NoSuchAlgorithmException | 
                         InvalidKeyException | 
                         NoSuchProviderException | 
                         SignatureException e) {}
            }
        } else {
            try {
                certificate.verify( certificate.getPublicKey() );
                return certificate;
                
            } catch (CertificateException | 
                     NoSuchAlgorithmException | 
                     InvalidKeyException | 
                     NoSuchProviderException | 
                     SignatureException ex) {}
        }
        throw new TrustPathException(TrustPathException.NOT_AUTHORITIES);
    }
    
    public static PrivateKeyUsagePeriod getPrivateKeyValidity(X509Certificate certificate) 
    throws CertificateHelperException {
        ASN1Encodable asn1Enc = preProcessExtension(certificate, Extension.privateKeyUsagePeriod);
        
        return PrivateKeyUsagePeriod.getInstance(asn1Enc);
    }
    
    public static URL getURLOCSP(X509Certificate certificate) throws CertificateHelperException {
        try {
            ASN1Encodable asn1Enc = preProcessExtension(certificate, Extension.authorityInfoAccess);
            
            AccessDescription[] ad = AuthorityInformationAccess.getInstance(asn1Enc).getAccessDescriptions();
            int index = 0;
            do {
                if(ad[index].getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)) {
                    String info = ad[index].getAccessLocation().toString();
                    URL result = new URL(info.split(" ")[info.split(" ").length-1]);
                    
                    if(result.getPort() == -1) {
                        //De no poseer puerto específico, se modifica la URI para colocar puerto 80
                        result = new URL(result.getProtocol() + "://" + result.getHost() + ":80" + result.getPath());
                    }
                    return result;
                }
                
                index++;
            } while(index <= ad.length);
            
            throw new CertificateHelperException("");
            
        } catch (MalformedURLException | CertificateHelperException ex) {
            throw new CertificateHelperException(I18n.get(I18n.M_ERROR_OCSP_EXTRACT_URL));
        }
    }
    
    public static List<String> getCRLDistributionPoints(X509Certificate certificate) 
    throws CertificateHelperException {
        ASN1Encodable asn1Enc = preProcessExtension(certificate, Extension.cRLDistributionPoints);
        CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Enc);
        List<String> crlUrls = new ArrayList<>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null
                && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(genName.getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }
    
    private static ASN1Encodable preProcessExtension (
        X509Certificate certificate, 
        ASN1ObjectIdentifier extensionID
    ) throws CertificateHelperException {
        try {
            //OJO... Identificar si la extension se encuentra marcada como critica o no
            Extension extension = new Extension(
                extensionID, 
                false, 
                certificate.getExtensionValue(extensionID.getId())
            );
            ASN1Encodable asn1Enc = extension.getParsedValue();
            if (asn1Enc instanceof DEROctetString) {
                DEROctetString derOctetString = (DEROctetString)asn1Enc;
                asn1Enc = ANS1EncodableHelper.decode(derOctetString.getOctets());
            }
            
            return asn1Enc;
            
        } catch (ANS1EncodableHelperException | NullPointerException ex) {
            throw new CertificateHelperException(I18n.get(I18n.M_ERROR_EXTENSION_EXTRACT, extensionID.toString()));
        }
    }
}
