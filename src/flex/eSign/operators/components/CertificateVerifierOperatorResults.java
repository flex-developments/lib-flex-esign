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
 * Consulte la licencia GPL para mas details. Usted debe recibir una copia
 * de la GPL junto con este programa; si no, escriba a la Free Software
 * Foundation Inc. 51 Franklin Street,5 Piso, Boston, MA 02110-1301, USA.
 */

package flex.eSign.operators.components;

import flex.eSign.i18n.I18n;

/**
 * CertificateVerifierOperatorResults
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public final class CertificateVerifierOperatorResults {
    private boolean autorized = false;
    private String details = I18n.get(I18n.M_CERT_VERIFIER_RESULTS_DETAILS_INIT);
    private Throwable cause;
    
    public void setAutorized(boolean autorized, String details, Throwable cause) {
        this.autorized = autorized;
        this.details = details;
        this.cause = cause;
    }
            
    public boolean isAutorized() {
        return autorized;
    }
    
    public String getDetails() {
        return details;
    }
    
    public Throwable getCause() {
        return cause;
    }
}
