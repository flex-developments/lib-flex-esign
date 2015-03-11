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

package flex.eSign.operators.components;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * CertificateVerifierConfig
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public final class CertificateVerifierConfig {
    private X509Certificate certificate = null;
    private List<X509Certificate> authorities = null;
    private List<X509CRL> crls = null;
    
    private boolean verifyWithLCR = true;
    private boolean verifyWithOCSP = true;
    private boolean invalidOnOCSPFail = false;
    private boolean invalidOnCRLFail = false;
    private boolean invalidOnCRLandOCSPFail = true;
    private boolean verbose = false;
    
    private boolean tryDownloadCRL = true;
    private int ocspAttempts = 3;
    private int ocspAttemptsDelayInms = 1000;
    //--------------------------------------------------------------------------
    private List<String> ntpServers = null;
    private boolean invalidOnNTPFail = false;
    private boolean verifyDateWithNTP = false;
    private boolean verifyDateWithHost = true;
    
    private Date signDate = null;
    
    /**
     * Constructor para verificacion de certificado antes de generar firma.
     * @param certificate
     * @param authorities
     * @param crls
     * @param ntpServers 
     * @param verbose 
     * @return  
     */
    public static CertificateVerifierConfig getInstanceToNewSign(
        X509Certificate certificate,
        List<X509Certificate> authorities,
        List<X509CRL> crls,
        List<String> ntpServers,
        boolean verbose
    ) {
        CertificateVerifierConfig vcConfig = new CertificateVerifierConfig();
        vcConfig.setCertificate(certificate);
        vcConfig.setAuthorities(authorities);
        vcConfig.setCRLs(crls);
        vcConfig.setNtpServers(ntpServers);
        vcConfig.setVerbose(verbose);
        return vcConfig;
    }
    
    /**
     * Constructor para verificacion de certificado para una firma pre-existente.
     * @param certificate
     * @param authorities
     * @param crls
     * @param signDate 
     * @param verbose 
     * @return  
     */
    public static CertificateVerifierConfig getInstanceToOldSign(
        X509Certificate certificate,
        List<X509Certificate> authorities,
        List<X509CRL> crls,
        Date signDate,
        boolean verbose
    ) {
        CertificateVerifierConfig vcConfig = new CertificateVerifierConfig();
        vcConfig.setCertificate(certificate);
        vcConfig.setAuthorities(authorities);
        vcConfig.setCRLs(crls);
        vcConfig.setSignDate(signDate);
        vcConfig.setVerbose(verbose);
        return vcConfig;
    }
    
    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public List<X509Certificate> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<X509Certificate> authorityCertificates) {
        this.authorities = authorityCertificates;
    }

    public List<X509CRL> getCRLs() {
        return crls;
    }

    public void setCRLs(List<X509CRL> crls) {
        this.crls = crls;
        if(this.crls != null) verifyWithLCR = true;
    }
    
    public boolean isVerifyWithCRL() {
        return verifyWithLCR;
    }
    
    public List<String> getNtpServers() {
        return ntpServers;
    }
    
    public void setNtpServers(List<String> ntpServers) {
        this.ntpServers = new ArrayList<>();
        
        if(ntpServers != null)
            if(!ntpServers.isEmpty())
                for(String ntp : ntpServers)
                    if (!ntp.isEmpty())
                        this.ntpServers.add(ntp);
        
        if(this.ntpServers.isEmpty()) {
            this.ntpServers = null;
            this.verifyDateWithNTP = false;
        } else {
            this.verifyDateWithNTP = true;
        }
    }
    
    public boolean isVerifyDateWithNTP() {
        return verifyDateWithNTP;
    }
    
    public boolean isVerifyDateWithHost() {
        return verifyDateWithHost;
    }

    public void setVerifyDateWithHost(boolean verifyDateWithHost) {
        this.verifyDateWithHost = verifyDateWithHost;
    }
    
    public boolean isVerifyWithOCSP() {
        return verifyWithOCSP;
    }

    public void setVerifyWithOCSP(boolean verifyWithOCSP) {
        this.verifyWithOCSP = verifyWithOCSP;
    }

    public boolean isInvalidOnNTPFail() {
        return invalidOnNTPFail;
    }

    public void setInvalidOnNTPFail(boolean invalidOnNTPFail) {
        this.invalidOnNTPFail = invalidOnNTPFail;
    }
    
    public boolean isInvalidOnOCSPFail() {
        return invalidOnOCSPFail;
    }

    public void setInvalidOnOCSPFail(boolean invalidOnOCSPFail) {
        this.invalidOnOCSPFail = invalidOnOCSPFail;
    }
    
    public boolean isInvalidOnCRLFail() {
        return invalidOnCRLFail;
    }

    public void setInvalidOnCRLFail(boolean invalidOnCRLFail) {
        this.invalidOnCRLFail = invalidOnCRLFail;
    }
    
    public boolean isInvalidOnCRLandOCSPFail() {
        return invalidOnCRLandOCSPFail;
    }

    public void setInvalidOnCRLandOCSPFail(boolean invalidOnCRLandOCSPFail) {
        this.invalidOnCRLandOCSPFail = invalidOnCRLandOCSPFail;
    }

    public int getOCSPAttemptsDelayInms() {
        return ocspAttemptsDelayInms;
    }

    public void setOCSPAttemptsDelayInms(int ocspAttemptsDelayInms) {
        this.ocspAttemptsDelayInms = ocspAttemptsDelayInms;
    }

    public int getOCSPAttempts() {
        return ocspAttempts;
    }

    public void setOCSPAttempts(int ocspAttempts) {
        this.ocspAttempts = ocspAttempts;
    }

    public boolean isTryDownloadCRL() {
        return tryDownloadCRL;
    }

    public void setTryDownloadCRL(boolean tryDownloadCRL) {
        this.tryDownloadCRL = tryDownloadCRL;
    }

    public Date getSignDate() {
        return signDate;
    }

    public void setSignDate(Date signDate) {
        this.signDate = signDate;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }
}
