/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * 
 * Fuente original: "http://svn.apache.org/repos/asf/cxf/tags/cxf-2.4.3/distribution/src/main/release/samples/sts_issue_operation/src/main/java/demo/sts/provider/cert/CRLVerifier.java"
 * ---
 * Modificación apoyada por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com | flopez@suscerte.gob.ve
 * Ing. Yessica De Ascencao - yessicadeascencao@gmail.com | ydeascencao@suscerte.gob.ve
 */

package flex.eSign.helpers;

import flex.eSign.helpers.exceptions.CertificateHelperException;
import flex.eSign.helpers.exceptions.CRLHelperException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

/**
 * CRLHelper
 * 
 * @author Apache Software Foundation (ASF)
 * ----
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 */
public final class CRLHelper {
    final public static String NO_DISTRIBUTION_POINTS = "no-DP";
    
    public static X509CRL loadPEMCRL(InputStream inStream) throws CRLHelperException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(inStream);
            
        } catch (CRLException | CertificateException ex) {
            throw new CRLHelperException(ex);
        }
    }
    
    public static X509CRL crlFilter(X509Certificate issuer, List<X509CRL> crls) {
        List<X509CRL> candidates = new ArrayList<>();
        
        if(crls != null) {
            //Filtrar las LCRs para encontrar las pertenecientes al emisor
                for(X509CRL candidate : crls) {
                    try {
                        X500Principal idEmisor = issuer.getSubjectX500Principal();
                        if (!idEmisor.equals(candidate.getIssuerX500Principal()))
                            throw new CRLException(CRLHelperException.ERROR_CRL_NOT_ISSUED_BY_CA);

                        candidate.verify(issuer.getPublicKey());
                        candidates.add(candidate);

                    } catch (InvalidKeyException | 
                             NoSuchAlgorithmException | 
                             NoSuchProviderException | 
                             SignatureException | 
                             CRLException ex) {
                        //Si ocurre algún error durante la verificación de la LCR
                        //se descarta la candidata.
                        //Exception controlada
                    }
                }
                if( (candidates == null) || (candidates.isEmpty()) ) return null;
            
            //De las cadidatas se selecciona la más reciente
                X509CRL result = candidates.get(0);
                for(X509CRL candidate : candidates) {
                    if(candidate.getThisUpdate().after(result.getThisUpdate()))
                        result = candidate;
                }
            
            return result;
        }
        else return null;
    }
    
    /**
     * Descargar LCRs desde puntos de distribucion.
     * 
     * @param certificate
     * @param authorities
     * @return LinkedHashMap<String, Object> El String indicará el punto de distribución que se utilizó y el Object tendrá el resultado (Puede ser una Exception o un X509CRL
     */
    public static LinkedHashMap<String, Object> downloadCRLs(
        X509Certificate certificate,
        List<X509Certificate> authorities
    ) {
        
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();
        
        List<String> crlDistPoints = null;
        try {
            crlDistPoints = CertificateHelper.getCRLDistributionPoints(certificate);
            
        } catch (CertificateHelperException ex) {
            result.put(NO_DISTRIBUTION_POINTS, ex);
            return result;
        }
        
        for (String crlDP : crlDistPoints) {
            try {
                X509CRL lcr = downloadCRL(crlDP, authorities);
                result.put(crlDP, lcr);
                
            } catch (Exception ex) {
                ex = new CRLHelperException(CRLHelperException.ERROR_CRL_DOWNLOAD, ex);
                result.put(crlDP, ex);
            }

        }
        
        return result;
    }
    
    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based
     * URLs.
     * @param crlURL
     * @param sslAuthorities
     * @return 
     * @throws java.io.IOException 
     * @throws java.security.cert.CertificateException 
     * @throws java.security.cert.CRLException 
     * @throws flex.eSign.helpers.exceptions.CRLHelperException 
     * @throws javax.naming.NamingException 
     */
    public static X509CRL downloadCRL(
        String crlURL, 
        List<X509Certificate> sslAuthorities
    ) throws IOException,
             CertificateException, 
             CRLException,
             CRLHelperException, 
             NamingException {
        
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL, sslAuthorities);
            
        } else if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
            
        } else {
            throw new CRLHelperException(
                CRLHelperException.ERROR_CRL_DOWNLOAD_METHOD
                + " " + crlURL
            );
        }
    }

    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     * @param ldapURL
     * @return 
     * @throws java.security.cert.CertificateException 
     * @throws javax.naming.NamingException 
     * @throws java.security.cert.CRLException 
     * @throws flex.eSign.helpers.exceptions.CRLHelperException 
     */
    public static X509CRL downloadCRLFromLDAP(String ldapURL) 
    throws CertificateException, 
             NamingException, 
             CRLException,
             CRLHelperException {
        
        Map<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext((Hashtable)env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        
        if ((val == null) || (val.length == 0)) {
            throw new CRLHelperException(
                CRLHelperException.ERROR_CRL_DOWNLOAD
                +  " " + ldapURL
            );
            
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(inStream);
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     * @param crlURL
     * @param sslAuthorities
     * @return 
     * @throws java.io.IOException 
     * @throws java.security.cert.CertificateException 
     * @throws java.security.cert.CRLException 
     */
    public static X509CRL downloadCRLFromWeb(
        String crlURL,
        List<X509Certificate> sslAuthorities
    ) throws IOException, 
             CertificateException,
             CRLException {
        
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);
            for(X509Certificate trust : sslAuthorities) {
                ks.setCertificateEntry(CertificateHelper.getCN(trust), trust);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
            
            InputStream crlStream = null;
            
            try {
                URL url = new URL(crlURL);
                crlStream = url.openStream();
                
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL result = (X509CRL) cf.generateCRL(crlStream);

                return result;

            } finally {
                if (crlStream != null) crlStream.close();
            }

        } catch (CertificateHelperException | 
                 IOException | 
                 KeyManagementException | 
                 KeyStoreException | 
                 NoSuchAlgorithmException | 
                 CRLException | 
                 CertificateException ex) {
            throw new IOException(ex.getCause());
        }
    }
}
