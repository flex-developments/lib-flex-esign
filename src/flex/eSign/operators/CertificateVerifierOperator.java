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

package flex.eSign.operators;

import flex.eSign.helpers.CRLHelper;
import flex.eSign.helpers.CertificateHelper;
import flex.eSign.helpers.exceptions.CertificateHelperException;
import flex.eSign.i18n.I18n;
import flex.eSign.operators.components.CertificateVerifierConfig;
import flex.eSign.operators.components.CertificateVerifierOperatorResults;
import flex.eSign.operators.exceptions.CertificateVerifierOperatorException;
import flex.eSign.operators.exceptions.InvalidCertificateException;
import flex.eSign.operators.exceptions.NoCertificatStatusException;
import flex.eSign.operators.exceptions.OCSPFailException;
import flex.eSign.operators.exceptions.OCSPRequestException;
import flex.eSign.operators.exceptions.PrivateKeyExpiredException;
import flex.eSign.operators.exceptions.PrivateKeyInvalidException;
import flex.eSign.operators.exceptions.PrivateKeyNotYetException;
import flex.eSign.operators.exceptions.RevokedCertificateException;
import flex.eSign.operators.exceptions.TrustPathException;
import flex.helpers.LoggerHelper;
import flex.helpers.NTPHelper;
import flex.helpers.VirtualClockHelper;
import flex.helpers.exceptions.LoggerHelperException;
import flex.helpers.exceptions.NTPHelperException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;

/**
 * CertificateVerifierOperator
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @version 1.0
 */
public class CertificateVerifierOperator {
    //OJO... Falta implementar verificacion contra una TSA
    final private static String VERIFY_CERTIFICATE_WITH_DATE_SOURCE_LOCAL = VirtualClockHelper.DATE_SOURCE_LOCAL;
    final private static String VERIFY_CERTIFICATE_WITH_DATE_SOURCE_NTP = VirtualClockHelper.DATE_SOURCE_NTP;
    final private static String VERIFY_CERTIFICATE_WITH_DATE_SOURCE_TSS = VirtualClockHelper.DATE_SOURCE_TSS;
    final private static String VERIFY_CERTIFICATE_WITH_DATE_SOURCE_SIGN_DATE= "SIGN DATE";
    
    final public static String VERIFY_CERTIFICATE_WITH_CRL = "CRL";
    final public static String VERIFY_CERTIFICATE_WITH_OCSP = "OCSP";
    
    ////////////////////////// Operaciones Integrales //////////////////////////
    /**
     * Verificar un certificado antes de generar una firma electronica.
     * @param vcConfig
     * @return 
     */
    public static CertificateVerifierOperatorResults verifyToNewSignature(
        CertificateVerifierConfig vcConfig
    ) {
        CertificateVerifierOperatorResults results = new CertificateVerifierOperatorResults();
        String steps = writeInfoLog("Validacion de certificado para generar firmas", vcConfig.isVerbose());
        
        //0.Obtener fecha de NTP************************************************
            Date ntpDate = null;
            if (vcConfig.isVerifyDateWithNTP()) {
                steps = steps + writeInfoLog("\n > 0.Obteniendo hora ntp", vcConfig.isVerbose());
                try {
                    ntpDate = NTPHelper.getDateTime(vcConfig.getNtpServers(), null);

                } catch (NTPHelperException ex) {
                    if(vcConfig.isInvalidOnNTPFail()) {
                        results.setAutorized(
                            false, 
                            NTPHelperException.ERROR_NTP_CONECTION, 
                            new NTPHelperException(ex.getLocalizedMessage())
                        );
                        return results;
                    }
                }
            }
            
        //1.Filtrar autoridades para obtener cadena y determinar si está debajo de alguna autoridad de confianza
            List<X509Certificate> certPath = null;
            try {
                steps = steps + writeInfoLog("\n > 1.Filtrar autoridades", vcConfig.isVerbose());
                certPath = CertificateHelper.getAuthorities(
                    vcConfig.getCertificate(), 
                    vcConfig.getAuthorities()
                );

            } catch (TrustPathException ex) {
                results.setAutorized(false, ex.getLocalizedMessage(), ex);
                return results;
            }
        
        //2.Verificar fechas ***************************************************
            steps = steps + writeInfoLog("\n > 2.Verificar fechas", vcConfig.isVerbose());
            //2.1.Verificar fechas contra fuente local *************************
                steps = steps + writeInfoLog("\n >> 2.1.Verificar fechas contra fuente local", vcConfig.isVerbose());
                if (vcConfig.isVerifyDateWithHost()) {
                    try {
                        //2.1.1.Verificar fechas del certficado
                            steps = steps + writeInfoLog("\n >>> 2.1.1.Fechas del certificado", vcConfig.isVerbose());
                            verifiyCertificateValidityPeriod(
                                vcConfig.getCertificate(), 
                                new Date(), 
                                VERIFY_CERTIFICATE_WITH_DATE_SOURCE_LOCAL
                            );

                        //2.1.2.Verificar fechas de la clave privada
                            steps = steps + writeInfoLog("\n >>> 2.2.2.Fechas de la clave privada", vcConfig.isVerbose());
                            verifyPrivateKeyValidityPeriod(
                                vcConfig.getCertificate(), 
                                new Date(), 
                                VERIFY_CERTIFICATE_WITH_DATE_SOURCE_LOCAL
                            );

                    } catch (InvalidCertificateException ex) {
                        results.setAutorized(false, ex.getMessage(), ex);
                        return results;

                    } catch (PrivateKeyInvalidException ex) {
                        results.setAutorized(false, ex.getMessage(), ex);
                        return results;
                    }
                }
                
            //2.2.Verificar fechas contra fuente ntp ***************************
                steps = steps + writeInfoLog("\n >> 2.2.Verificar fechas contra fuente ntp", vcConfig.isVerbose());
                if ( (vcConfig.isVerifyDateWithNTP()) && (ntpDate != null) ) {
                    try {
                        //2.2.1.Verificar fechas del certficado
                            steps = steps + writeInfoLog("\n >>> 2.2.1.Fechas del certificado", vcConfig.isVerbose());
                            verifiyCertificateValidityPeriod(
                                vcConfig.getCertificate(), 
                                ntpDate, 
                                VERIFY_CERTIFICATE_WITH_DATE_SOURCE_NTP
                            );

                        //2.2.2.Verificar fechas de la clave privada
                            steps = steps + writeInfoLog("\n >>> 2.2.2.Fechas de la clave privada", vcConfig.isVerbose());
                            verifyPrivateKeyValidityPeriod(
                                vcConfig.getCertificate(), 
                                ntpDate, 
                                VERIFY_CERTIFICATE_WITH_DATE_SOURCE_NTP
                            );

                    } catch (InvalidCertificateException ex) {
                        results.setAutorized(false, ex.getMessage(), ex);
                        return results;

                    } catch (PrivateKeyInvalidException ex) {
                        results.setAutorized(false, ex.getMessage(), ex);
                        return results;
                    }
                }
        
        //3.Verificar certificado contra cadena y OCSP**************************
            boolean successOCSP = false; //Variable para controlar si paso la verificacion OCSP
            steps = steps + writeInfoLog("\n > 3.Verificar certificado contra cadena y OCSP", vcConfig.isVerbose());
            //3.1.Verificar contra cadena y OCSP usando fuente local ***********
                CertificateVerifierOperatorResults aux = new CertificateVerifierOperatorResults();
                aux.setAutorized(true, null, null);
                
                //OJO... Revisar
                //if ( (vcConfig.isVerifyDateWithHost()) || (!vcConfig.isVerifyDateWithNTP()) ) {
                if (vcConfig.isVerifyDateWithHost()) {
                    steps = steps + writeInfoLog("\n >> 3.1.Verificar contra cadena y OCSP usando fuente local", vcConfig.isVerbose());
                    aux = verifyWithCertPathAndOCSP(
                            vcConfig.getCertificate(),
                            certPath,
                            vcConfig.isVerifyWithOCSP(),
                            vcConfig.getOCSPAttempts(), 
                            vcConfig.getOCSPAttemptsDelayInms(),
                            new Date(),
                            vcConfig.isInvalidOnOCSPFail(), 
                            vcConfig.isVerbose()
                    );
                }
            //3.2.Verificar contra cadena y OCSP usando fuente ntp *************
                if ( (vcConfig.isVerifyDateWithNTP()) && (ntpDate != null) ) {
                    steps = steps + writeInfoLog("\n >> 3.2.Verificar contra cadena y OCSP usando fuente ntp", vcConfig.isVerbose());
                    aux = verifyWithCertPathAndOCSP(
                        vcConfig.getCertificate(),
                        certPath,
                        vcConfig.isVerifyWithOCSP(),
                        vcConfig.getOCSPAttempts(), 
                        vcConfig.getOCSPAttemptsDelayInms(),
                        ntpDate,
                        vcConfig.isInvalidOnOCSPFail(), 
                        vcConfig.isVerbose()
                    );
                }
                
            if(!aux.isAutorized()) {
                steps = steps + writeInfoLog("\n >>> " + aux.getDetails(), vcConfig.isVerbose());
                results.setAutorized(false, steps, aux.getCause());
                return results;
            }
            else successOCSP = true;
            
        //4.Verificar certificado contra LCR************************************
            boolean successCRL = false; //Variable para controlar si pasó la verificación LCR
            if(vcConfig.isVerifyWithCRL()) {
                steps = steps + writeInfoLog("\n > 4.Verificar certificado contra LCR", vcConfig.isVerbose());
                CertificateVerifierOperatorResults aux2 = new CertificateVerifierOperatorResults();
                aux2.setAutorized(true, null, null);
                
                //4.1.Verificar contra LCR usando fuente local *****************
                    //OJO... Revisar
                    //if ( (vcConfig.isVerifyDateWithHost()) || (!vcConfig.isVerifyDateWithNTP()) ) {
                    if (vcConfig.isVerifyDateWithHost()) {
                        steps = steps + writeInfoLog("\n >> 4.1.Verificar contra LCR usando fuente local", vcConfig.isVerbose());
                        aux2 = verifyWithCRL(
                            vcConfig.getCertificate(),
                            vcConfig.getAuthorities(),
                            certPath,
                            vcConfig.getCRLs(),
                            vcConfig.isTryDownloadCRL(),
                            new Date(),
                            vcConfig.isInvalidOnCRLFail(), 
                            vcConfig.isVerbose()
                        );
                    }
                    
                //4.2.Verificar contra LCR usando fuente ntp *******************
                    if ( (vcConfig.isVerifyDateWithNTP()) && (ntpDate != null) ) {
                        steps = steps + writeInfoLog("\n >> 4.2.Verificar contra LCR usando fuente ntp", vcConfig.isVerbose());
                        aux2 = verifyWithCRL(
                            vcConfig.getCertificate(),
                            vcConfig.getAuthorities(),
                            certPath,
                            vcConfig.getCRLs(),
                            vcConfig.isTryDownloadCRL(),
                            ntpDate,
                            vcConfig.isInvalidOnCRLFail(), 
                            vcConfig.isVerbose()
                        );
                    }
                    
                if(!aux2.isAutorized()) {
                    steps = steps + writeInfoLog("\n >>> " + aux2.getDetails(), vcConfig.isVerbose());
                    results.setAutorized(false, steps, aux2.getCause());
                    return results;
                }
                else successCRL = true;
            }
        
        //5.Verificar comprobacion OCSP y LCR **********************************
            steps = steps + writeInfoLog("\n > 5.Verificar comprobacion OCSP y LCR", vcConfig.isVerbose());
            if( (successOCSP == false) && (successCRL == false) )
                if(vcConfig.isInvalidOnCRLandOCSPFail())
                    results.setAutorized(
                        false, 
                        NoCertificatStatusException.NO_CERTIFICATE_ESTATUS, 
                        new NoCertificatStatusException(
                    ));
        
        //6.Todas las verificaciones superadas
            results.setAutorized(true, steps, null);
            
        return results;
    }
    
    /**
     * Verificar Certificado en el momento en que se generó una firma electronica.
     * @param vcConfig
     * @return
     * @throws CertificateVerifierOperatorException 
     */
    public static CertificateVerifierOperatorResults verifyToOldSignature(
        CertificateVerifierConfig vcConfig
    ) throws CertificateVerifierOperatorException {
        if(vcConfig.getSignDate() == null)
            throw new CertificateVerifierOperatorException(CertificateVerifierOperatorException.ERROR_SIGN_DATE_NULL);
        
        CertificateVerifierOperatorResults results = new CertificateVerifierOperatorResults();
        String steps = writeInfoLog("Validacion de certificado para firmas pre-existentes", vcConfig.isVerbose());
            
        //1.Filtrar autoridades para obtener cadena y determinar si está debajo de alguna autoridad de confianza
            List<X509Certificate> certPath = null;
            try {
                steps = steps + writeInfoLog("\n > 1.Filtrar autoridades", vcConfig.isVerbose());
                certPath = CertificateHelper.getAuthorities(
                    vcConfig.getCertificate(), 
                    vcConfig.getAuthorities()
                );

            } catch (TrustPathException ex) {
                results.setAutorized(false, ex.getLocalizedMessage(), ex);
                return results;
            }
        
        //2.Verificar fechas ***************************************************
            steps = steps + writeInfoLog("\n > 2.Verificar fechas", vcConfig.isVerbose());
            try {
                //2.1.Verificar fechas del certficado
                    steps = steps + writeInfoLog("\n >> 2.1.Fechas del certificado", vcConfig.isVerbose());
                    verifiyCertificateValidityPeriod(
                        vcConfig.getCertificate(), 
                        vcConfig.getSignDate(), 
                        VERIFY_CERTIFICATE_WITH_DATE_SOURCE_SIGN_DATE
                    );
                    
                //2.2.Verificar fechas del certficado
                    steps = steps + writeInfoLog("\n >> 2.2.Fechas de la clave privada", vcConfig.isVerbose());
                    verifyPrivateKeyValidityPeriod(
                        vcConfig.getCertificate(), 
                        vcConfig.getSignDate(), 
                        VERIFY_CERTIFICATE_WITH_DATE_SOURCE_SIGN_DATE
                    );

            } catch (InvalidCertificateException ex) {
                results.setAutorized(false, ex.getMessage(), ex);
                return results;

            } catch (PrivateKeyInvalidException ex) {
                results.setAutorized(false, ex.getMessage(), ex);
                return results;
            }
        
        
        //3.Verificar certificado contra cadena y OCSP**************************
            boolean successOCSP = false; //Variable para controlar si paso la verificacion OCSP
            steps = steps + writeInfoLog("\n > 3.Certificado contra cadena y OCSP", vcConfig.isVerbose());       
            CertificateVerifierOperatorResults aux = 
                verifyWithCertPathAndOCSP(
                    vcConfig.getCertificate(),
                    certPath,
                    vcConfig.isVerifyWithOCSP(),
                    vcConfig.getOCSPAttempts(), 
                    vcConfig.getOCSPAttemptsDelayInms(),
                    vcConfig.getSignDate(),
                    vcConfig.isInvalidOnOCSPFail(), 
                    vcConfig.isVerbose()
            );
            if(!aux.isAutorized()) {
                steps = steps + writeInfoLog("\n >> " + aux.getDetails(), vcConfig.isVerbose());
                results.setAutorized(false, steps, aux.getCause());
                return results;
            }
            else successOCSP = true;
        
        //4.Verificar certificado contra LCR************************************
            boolean successCRL = false; //Variable para controlar si pasó la verificación LCR
            if(vcConfig.isVerifyWithCRL()) {
                steps = steps + " > 4.Certificado contra LCR";
                CertificateVerifierOperatorResults aux2 = 
                    verifyWithCRL(
                        vcConfig.getCertificate(),
                        vcConfig.getAuthorities(),
                        certPath,
                        vcConfig.getCRLs(),
                        vcConfig.isTryDownloadCRL(),
                        vcConfig.getSignDate(),
                        vcConfig.isInvalidOnCRLFail(), 
                        vcConfig.isVerbose()
                );
                if(!aux2.isAutorized()) {
                    steps = steps + writeInfoLog("\n >> " + aux2.getDetails(), vcConfig.isVerbose());
                    results.setAutorized(false, steps, aux2.getCause());
                    return results;
                }
                else successCRL = true;
            }
        
        //5.Verificar comprobacion OCSP y LCR **********************************
            steps = steps + writeInfoLog("\n > 5.Verificar comprobacion OCSP y LCR", vcConfig.isVerbose());
            if( (successOCSP == false) && (successCRL == false) )
                if(vcConfig.isInvalidOnCRLandOCSPFail())
                    results.setAutorized(
                        false, 
                        NoCertificatStatusException.NO_CERTIFICATE_ESTATUS, 
                        new NoCertificatStatusException(
                    ));
        
        //6.Todas las verificaciones superadas
            results.setAutorized(true, steps, null);
            
        return results;
    }
    ////////////////////////////////////////////////////////////////////////////
    
    /////////////////// Operaciones Integrales de 2do Nivel ////////////////////
    private static CertificateVerifierOperatorResults verifyWithCertPathAndOCSP(
        X509Certificate certificate,
        List<X509Certificate> authorities,
        boolean ocspEnabled,
        int ocspAttempts, 
        int timeBeforeAttempt,
        Date date,
        boolean invalidOnOCSPFail, 
        boolean genLog
    ) {
        
        CertificateVerifierOperatorResults results = new CertificateVerifierOperatorResults();
        
        try {
            List<X509Certificate> aux = new ArrayList<>();
            aux.add(certificate);
            
            //Verificar certificado contra OCSP para su uso en la fecha indicada
            verifyWithCertPathAndOCSP(
                aux, 
                authorities, 
                ocspEnabled,
                CertificateHelper.getURLOCSP(certificate).toString(), 
                ocspAttempts, 
                timeBeforeAttempt,
                date, 
                genLog
            );
            
        } catch (RevokedCertificateException ex) {
            results.setAutorized(false, ex.getMessage(), ex);
            return results;
            
        } catch (TrustPathException ex) {
            results.setAutorized(false, ex.getMessage(), ex.getCause());
            return results;
            
        } catch (OCSPRequestException | OCSPFailException ex) {
            //Error al construir la petición OCSP
            if(invalidOnOCSPFail) {
                results.setAutorized(false, ex.getMessage(), ex);
                return results;
            }
            
        } catch (CertificateHelperException ex) {
            //No se encontró URL del OCSP dentro del certificado
        }
        
        results.setAutorized(true, VERIFY_CERTIFICATE_WITH_OCSP, null);
        return results;
    }
    
    private static CertificateVerifierOperatorResults verifyWithCRL(
        X509Certificate certificate,
        List<X509Certificate> sslAuthorities,
        List<X509Certificate> authorities,
        List<X509CRL> crls,
        boolean tryCRLDownload,
        Date date,
        boolean invalidOnCRLFail, 
        boolean genLog
    ) {
        
        CertificateVerifierOperatorResults results = new CertificateVerifierOperatorResults();
        
        try {
            List<X509CRL> candidatesCRL = null;
            
            //Intentar descargar las CRLs de los diferentes puntos de distribucion
                if(tryCRLDownload){
                    LinkedHashMap<String, Object> downloaded = 
                            CRLHelper.downloadCRLs( certificate, sslAuthorities );

                    //Recorro los resultados obtenidos y proceso sólo las LCR
                    for(String key: downloaded.keySet()) {
                        if(key.compareTo(CRLHelper.NO_DISTRIBUTION_POINTS) == 0) {
                            //Si no se encontraron puntos de distribucion se manda al log
                            try {
                                writeWarningLog(
                                    "No se pudieron obtener los Distribution Points del certificado "
                                    + CertificateHelper.getCN(certificate) + downloaded.get(key)
                                    , genLog
                                );

                            } catch(CertificateHelperException ex) {
                                writeWarningLog(
                                    "No se pudieron obtener los Distribution Points del certificado "
                                    + downloaded.get(key)
                                    , genLog
                                );
                            }

                        } else {
                            Object o = downloaded.get(key);
                            //Se analiza el objeto obtenido del proceso de descarga
                            //Si es una LCR se procesa y si es una Exception se manda al log
                            if(o instanceof X509CRL) {
                                if (candidatesCRL != null) candidatesCRL.add( (X509CRL) o );
                                
                            } else {
                                writeWarningLog(
                                    ((Exception) o).getLocalizedMessage()
                                    , genLog
                                );
                            }   
                        }
                    }
                }
            
            //Agregar a las CRLs candidatas las CRLs obtenidas por parámetro
                candidatesCRL.addAll(crls);
            
            //Filtrar las CRLs candidatas para obtener la mas apropiada
                X509CRL crl;
                try {
                    crl = CRLHelper.crlFilter(
                        CertificateHelper.getIssuer(certificate, authorities),
                        candidatesCRL
                    );

                } catch (TrustPathException ex) {
                    results.setAutorized(false, ex.getMessage(), ex);
                    return results;
                }
            
            //Verificar certificado contra LCR para su uso en la fecha indicada
                verifyCertificateWithCRL(certificate, crl, date);

        } catch (NullPointerException ex) {
            //No se logra la conexion
            if(invalidOnCRLFail) {
                results.setAutorized(false, ex.getMessage(), ex);
                return results;
            }

        } catch (RevokedCertificateException ex) {
            results.setAutorized(false, ex.getMessage(), ex);
            return results;
        }
        
        results.setAutorized(true, VERIFY_CERTIFICATE_WITH_OCSP, null);
        return results;
    }
    ////////////////////////////////////////////////////////////////////////////
    
    ///////////////////////////// Operaciones Base /////////////////////////////
    /**
     * Verificar validez del certificado perse.
     * @param certificate
     * @param currentDate
     * @param verificationMethod
     * @throws InvalidCertificateException 
     */
    public static void verifiyCertificateValidityPeriod(
        X509Certificate certificate, 
        Date currentDate, 
        String verificationMethod
    ) throws InvalidCertificateException {
        
        try {
            certificate.checkValidity(currentDate);

        } catch( CertificateNotYetValidException | CertificateExpiredException ex) {
            throw new InvalidCertificateException(verificationMethod, ex);
            
        }
    }
    
    /**
     * Verificar validez de la clave privada.
     * @param certificate
     * @param currentDate
     * @param verificationMethod
     * @throws PrivateKeyInvalidException 
     */
    public static void verifyPrivateKeyValidityPeriod(
        X509Certificate certificate, 
        Date currentDate, 
        String verificationMethod
    ) throws PrivateKeyInvalidException {
        
        try {
            PrivateKeyUsagePeriod period = CertificateHelper.getPrivateKeyValidity(certificate);

            if(currentDate.before(period.getNotBefore().getDate())) 
                throw new PrivateKeyInvalidException(verificationMethod, new PrivateKeyNotYetException());
            
            if(currentDate.after(period.getNotAfter().getDate()))
                throw new PrivateKeyInvalidException(verificationMethod, new PrivateKeyExpiredException());
            
        } catch (ParseException | CertificateHelperException ex) {
            //Esta excepcion ocurre cuando se intenta buscar una extensión en el certificado
            //no hacer nada.
        }
    }
    
    /**
     * Verificar certificado contra LCR para un instante determinado.
     * @param certificate
     * @param crl
     * @param date
     * @throws RevokedCertificateException
     * @throws NullPointerException 
     */
    public static void verifyCertificateWithCRL(
        X509Certificate certificate, 
        X509CRL crl,
        Date date
    ) throws RevokedCertificateException, NullPointerException {
        
        //NullPointerException si la LCR es NULL
        if(crl == null)
            throw new NullPointerException(I18n.get(I18n.M_ERROR_CERTIFICATE_VERIFY_CRL_NO_CRL_FOUND));
        if(date == null)
            throw new NullPointerException(I18n.get(I18n.M_ERROR_CERTIFICATE_VERIFY_NO_VERIFICATION_DATE));
        
        X509CRLEntry reg = crl.getRevokedCertificate(certificate);
        
        if( (reg != null) && 
            ( (date.after(reg.getRevocationDate())) || (date.equals(reg.getRevocationDate())) ) 
        )
            throw new RevokedCertificateException(
                CertificateVerifierOperator.VERIFY_CERTIFICATE_WITH_CRL, 
                reg.getRevocationDate(), 
                reg.getRevocationReason(), 
                reg.getCertificateIssuer(),
                null
            );
    }
    
    /**
     * Verificar certificados, su cadena de confianza, y estatus contra OCSP 
     * para un instante determinado.
     * @param certificates
     * @param authorities
     * @param ocspEnabled
     * @param ocspURL
     * @param ocspAttempts
     * @param timeBeforeAttempt
     * @param date
     * @param genLog
     * @throws RevokedCertificateException
     * @throws OCSPRequestException
     * @throws OCSPFailException
     * @throws TrustPathException 
     */
    public static void verifyWithCertPathAndOCSP(
        List<X509Certificate> certificates, 
        List<X509Certificate> authorities, 
        boolean ocspEnabled,
        String ocspURL, 
        int ocspAttempts, 
        int timeBeforeAttempt,
        Date date, 
        boolean genLog
    )  throws RevokedCertificateException,
              OCSPRequestException, 
              OCSPFailException, 
              TrustPathException {
        
        if(date == null)
            throw new NullPointerException(I18n.get(I18n.M_ERROR_CERTIFICATE_VERIFY_NO_VERIFICATION_DATE));
        
        if( (authorities==null) || (authorities.size()<1) )
            throw new TrustPathException(TrustPathException.NOT_AUTHORITIES);
        
        try {
            //Instantiate a CertificateFactory for X.509
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            //Extract the certification path from the List of Certificates
            CertPath certPath = cf.generateCertPath(certificates);

            //Create CertPathValidator that implements the "PKIX" algorithm
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            
            //Set the Trust anchor
            TrustAnchor anchor = null;
            for(X509Certificate cert : authorities) {
                anchor = new TrustAnchor(cert, null);
            }
            if(anchor==null)
                throw new TrustPathException(TrustPathException.NOT_AUTHORITIES);
            
            //The list of additional signer certificates for populating the trust store
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(true);
            
            //Set the PKIX parametersthrows TrustPathException
            Security.setProperty("ocsp.enable", Boolean.toString(ocspEnabled));
            Security.setProperty("ocsp.responderURL", ocspURL);

            //Validate and obtain results
            for(int i = 1; i <= ocspAttempts; i++) {
                try {
                    certPathValidator.validate(certPath, params);
                    break;
                    
                } catch (CertPathValidatorException ex) {
                    if(ex.getCause() instanceof IOException) {
                        //No se pudo contactar al OCSP
                        try {
                            ex = null;
                            Thread.sleep(timeBeforeAttempt);
                            if(i == ocspAttempts) throw new OCSPFailException(i);
                            CertificateVerifierOperator.writeWarningLog(I18n.get(I18n.M_CERT_VERIFIER_OCSP_RETRY), genLog);
                             
                        } catch (InterruptedException ex2) {}
                        
                    } else if(ex.getCause() instanceof CertificateRevokedException) {
                        //El certificado está revocado
                        CertificateRevokedException e = (CertificateRevokedException) ex.getCause();
                        
                        throw new RevokedCertificateException(
                            CertificateVerifierOperator.VERIFY_CERTIFICATE_WITH_OCSP,
                            e.getRevocationDate(),
                            e.getRevocationReason(),
                            e.getAuthorityName(),
                            e.getExtensions()
                        );
                        
                    } else if(ex.getReason().equals(CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS)) {
                        //No se pudo determinar el estado del certificado porque está desactivada la comprobación OCSP
                        //No se hace nada.
                    } else {
                        CertificateVerifierOperator.writeErrorLog(ex.getMessage(), genLog);
                        throw new TrustPathException(ex.getMessage());
                    }
                }
            }
            
        } catch (CertificateException ex) {
            if (ex instanceof RevokedCertificateException) {
                RevokedCertificateException revoc = (RevokedCertificateException)ex;
                if( (date.after(revoc.getRevocationDate())) || (date.equals(revoc.getRevocationDate())) )
                    throw revoc;
                
            } else {
                throw new OCSPRequestException(OCSPRequestException.ERROR_OCSP_REQUEST, ex);
            }
        
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw new OCSPRequestException(OCSPRequestException.ERROR_OCSP_REQUEST, ex);
            
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    
    /////////////////////////////////// Logs ///////////////////////////////////
    private static final LoggerHelper logger = new LoggerHelper("CertificateVerifierLogger", LoggerHelper.LOG_TYPE_SINGLE_DATED);
    
    public static String writeInfoLog(String message, boolean verbose) {
        if(verbose) logger.writeInfoLog(message);
        return message;
    }
    
    public static String writeWarningLog(String message, boolean verbose) {
        if(verbose) logger.writeWarningLog(message);
        return message;
    }
    
    public static String writeErrorLog(String message, boolean verbose) {
        if(verbose) logger.writeErrorLog(message);
        return message;
    }
    
    public static void setLogsType(int LogType) throws LoggerHelperException {
        logger.setLogType(LogType);
    }
    ////////////////////////////////////////////////////////////////////////////
}
