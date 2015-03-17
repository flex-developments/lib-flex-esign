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

package flex.eSign.operators.exceptions;

import flex.eSign.i18n.I18n;

/**
 * PKCS7SignOperatorException
 * Clase para indicar errores ocurridos durante la generación o verificación
 * de firma electrónica pkcs#7, los detalles del error se indican en el mensaje 
 * del constructor, además posee una serie de atributos estáticos referentes
 * a mensajes de error comunes durante la generación o verificación de la
 * firma electrónica pkcs#7.
 *
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class PKCS7SignOperatorException extends Exception {
    final public static String ERROR_PKCS7_SIGN_NOT_FORMAT = I18n.get(I18n.M_ERROR_PKCS7_SIGN_NOT_FORMAT);
    
    public PKCS7SignOperatorException(String message) {
        super(message);
    }
    
    public PKCS7SignOperatorException(Throwable ex) {
        super(ex);
    }
}
