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

import flex.eSign.operators.components.CertificateVerifierConfig;
import flex.eSign.operators.components.CertificateVerifierOperatorResults;

/**
 * PeriodicCertificateVerifierOperator
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @version 1.0
 */
public class PeriodicCertificateVerifierOperator {
    private static CertificateVerifierOperatorThreat verifier = null;
    
    /**
     * Iniciar verificacion periodica de certificado antes de generar una firma electronica.
     * @param vcConfig
     * @param certificateIntervalVerification
     * @return 
     */
    public static CertificateVerifierOperatorResults runPeriodicVerificationToNewSignature(
        CertificateVerifierConfig vcConfig,
        int certificateIntervalVerification
    ) {
        if(verifier == null) {
            verifier = new CertificateVerifierOperatorThreat(vcConfig, certificateIntervalVerification);
            verifier.start();
        }
        
        if(verifier.getCertificateIntervalVerification() != certificateIntervalVerification)
            verifier.setCertificateIntervalVerification(certificateIntervalVerification);
        
        if(verifier.getVcConfig() != vcConfig)
            verifier.setVcConfig(vcConfig);
        
        return verifier.getCertificateVerifyResults();
    }
    
    /**
     * Detener verificacion periodica de certificado antes de generar una firma electronica.
     */
    public static void interruptPeriodicVerificationToNewSignature() {
        if(verifier != null) {
            verifier.interrupt();
            verifier = null;
            System.gc();
        }
    }
}
    

final class CertificateVerifierOperatorThreat extends Thread {
    private int certificateIntervalVerification = 60000; //1 minute by default
    private CertificateVerifierConfig vcConfig = null;
    private CertificateVerifierOperatorResults certificateVerifyResults = null;
            
    public CertificateVerifierOperatorThreat(
        CertificateVerifierConfig vcConfig, 
        int certificateIntervalVerification) 
    {
        this.vcConfig = vcConfig;
        this.certificateIntervalVerification = certificateIntervalVerification;
    }
    
    @Override
    public void run() {
        verify();
        this.threatSleep(certificateIntervalVerification);
    }
    
    private void verify() {
        certificateVerifyResults = CertificateVerifierOperator.verifyToNewSignature(vcConfig);
    }
    
    private void threatSleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    public int getCertificateIntervalVerification() {
        return certificateIntervalVerification;
    }

    public void setCertificateIntervalVerification(int certificateIntervalVerification) {
        if(certificateIntervalVerification > 0)
            this.certificateIntervalVerification = certificateIntervalVerification;
    }

    public CertificateVerifierConfig getVcConfig() {
        return vcConfig;
    }

    public void setVcConfig(CertificateVerifierConfig vcConfig) {
        this.vcConfig = vcConfig;
        verify();
    }

    public CertificateVerifierOperatorResults getCertificateVerifyResults() {
        if (certificateVerifyResults == null) verify();
        return certificateVerifyResults;
    }
}
