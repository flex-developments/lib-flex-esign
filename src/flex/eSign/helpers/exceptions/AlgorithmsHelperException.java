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

package flex.eSign.helpers.exceptions;

import flex.eSign.i18n.I18n;
import java.security.NoSuchAlgorithmException;

/**
 * CRLHelperException
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public class AlgorithmsHelperException extends NoSuchAlgorithmException {
    final public static String ERROR_UNKNOWN_ALGORITHMS = I18n.get(I18n.M_ERROR_UNKNOWN_ALGORITHMS);
    final public static String ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE = I18n.get(I18n.M_ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE);
    
    public AlgorithmsHelperException(String message) {
        super(message);
    }
    
    public AlgorithmsHelperException(Throwable ex) {
        super(ex);
    }
    
    public AlgorithmsHelperException(String message, Throwable ex) {
        super(message, ex);
    }
}
