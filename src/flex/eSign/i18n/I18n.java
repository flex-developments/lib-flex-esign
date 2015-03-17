/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments en gmail
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments en gmail | flopez en suscerte gob ve
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

package flex.eSign.i18n;

import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * I18n
 * Clase estatica para controlar la internacionalizacion de los mensajes de la
 * libreria.
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @version 1.0
 */
public class I18n {
    private static String LANG_PATH = "flex/eSign/i18n/LANG";
    private static Locale LANGUAGE = Locale.forLanguageTag("es-VE");
    private static ResourceBundle bundle = ResourceBundle.getBundle(LANG_PATH, LANGUAGE);
    
    //List Resource Keys........................................................
    final public static String I_PDF_SIGN_LABEL_CONTENT = "I_PDF_SIGN_LABEL_CONTENT";
    
    final public static String M_CERT_VERIFIER_RESULTS_DETAILS_INIT = "M_CERT_VERIFIER_RESULTS_DETAILS_INIT";
    final public static String M_CERT_VERIFIER_OCSP_RETRY = "M_CERT_VERIFIER_OCSP_RETRY";
    
    final public static String M_ERROR_SIGN_STANDARD_NOT_SUPPORTED = "M_ERROR_SIGN_STANDARD_NOT_SUPPORTED";
    final public static String M_ERROR_UNKNOWN_ALGORITHMS = "M_ERROR_UNKNOWN_ALGORITHMS";
    final public static String M_ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE = "M_ERROR_ALGORITHMS_NOT_SUPPORTED_BY_DEVICE";
    final public static String M_ERROR_NULL_PROVIDER = "M_ERROR_NULL_PROVIDER";
    final public static String M_ERROR_OCSP_EXTRACT_URL = "M_ERROR_OCSP_EXTRACT_URL";
    final public static String M_ERROR_EXTENSION_EXTRACT = "M_ERROR_EXTENSION_EXTRACT";
    final public static String M_ERROR_BASIC_SIGN_NOT_FORMAT = "M_ERROR_BASIC_SIGN_NOT_FORMAT";
    final public static String M_ERROR_DATED_SIGN_NOT_FORMAT = "M_ERROR_DATED_SIGN_NOT_FORMAT";
    final public static String M_ERROR_PKCS7_SIGN_NOT_FORMAT = "M_ERROR_PKCS7_SIGN_NOT_FORMAT";
    final public static String M_ERROR_CRL_DOWNLOAD = "M_ERROR_CRL_DOWNLOAD";
    final public static String M_ERROR_CRL_DOWNLOAD_METHOD = "M_ERROR_CRL_DOWNLOAD_METHOD";
    final public static String M_ERROR_PRIVATE_KEY_INVALID = "M_ERROR_PRIVATE_KEY_INVALID";
    final public static String M_ERROR_CETIFICATE_INVALID = "M_ERROR_CETIFICATE_INVALID";
    final public static String M_ERROR_SIGN_GENERATION_PROCESS = "M_ERROR_SIGN_GENERATION_PROCESS";
    final public static String M_ERROR_SIGN_VERIFICATION_PROCESS = "M_ERROR_SIGN_VERIFICATION_PROCESS";
    final public static String M_ERROR_SIGN_ENCODE = "M_ERROR_SIGN_ENCODE";
    final public static String M_ERROR_CERITIFICATE_EXCEPTION_MESSAGE = "M_ERROR_CERITIFICATE_EXCEPTION_MESSAGE";
    final public static String M_ERROR_SIGN_DATE_NULL = "M_ERROR_SIGN_DATE_NULL";
    final public static String M_ERROR_ADD_DATE = "M_ERROR_ADD_DATE";
    final public static String M_ERROR_OCSP_FAIL = "M_ERROR_OCSP_FAIL";
    final public static String M_ERROR_NO_CERTIFICATE_ESTATUS = "M_ERROR_NO_CERTIFICATE_ESTATUS";
    final public static String M_ERROR_PDF_SIGN_DATE_NULL = "M_ERROR_PDF_SIGN_DATE_NULL";
    final public static String M_ERROR_OCSP_REQUEST = "M_ERROR_OCSP_REQUEST";
    final public static String M_ERROR_PRIVATE_KEY_NOT_YET = "M_ERROR_PRIVATE_KEY_NOT_YET";
    final public static String M_ERROR_PRIVATE_KEY_EXCEPTION = "M_ERROR_PRIVATE_KEY_EXCEPTION";
    final public static String M_ERROR_PRIVATE_KEY_EXPIRED = "M_ERROR_PRIVATE_KEY_EXPIRED";
    final public static String M_ERROR_CERITIFICATE_REVOKED = "M_ERROR_CERITIFICATE_REVOKED";
    final public static String M_ERROR_NOT_AUTHORITIES = "M_ERROR_NOT_AUTHORITIES";
    final public static String M_ERROR_CRL_NOT_ISSUED_BY_CA = "M_ERROR_CRL_NOT_ISSUED_BY_CA";
    final public static String M_ERROR_CERTIFICATE_VERIFY_CRL_NO_CRL_FOUND = "M_ERROR_CERTIFICATE_VERIFY_CRL_NO_CRL_FOUND";
    final public static String M_ERROR_CERTIFICATE_VERIFY_NO_VERIFICATION_DATE = "M_ERROR_CERTIFICATE_VERIFY_NO_VERIFICATION_DATE";
    //--------------------------------------------------------------------------
    
    /**
     * Obtener String internacionalizado.
     * 
     * @param key Clave del string dentro del bundle.
     * 
     * @return valor de la clave dentro del bundle.
     */
    public static String get(String key) {
        return bundle.getBundle(LANG_PATH, LANGUAGE).getString(key);
    }
    
    /**
     * Obtener String internacionalizado con formato.
     * 
     * @param key Clave del string dentro del bundle.
     * @param arguments Argumentos para el formato.
     * 
     * @return valor de la clave dentro del bundle con formato procesado.
     */
    public static String get(String key, Object ... arguments) {
        MessageFormat temp = new MessageFormat(get(key));
        return temp.format(arguments);
    }
    
    /**
     * Obtener todas las keys del buundle.
     * 
     * @return Enumeration de las keys.
     */
    public static Enumeration<String> getKeys() {
        return bundle.getKeys();
    }
    
    /**
     * Obtener el lenguaje utilizado por la libreria para la internacionalizacion
     * de los mensajes.
     * 
     * @return Lenguaje para la internacionalizacion de los mensajes.
     */
    public static Locale getLanguage() {
        return LANGUAGE;
    }
    
    /**
     * Establecer el lenguaje utilizado por la libreria para la internacionalizacion
     * de los mensajes.
     * Ejemplos:
     *      I18n.setLanguage(es);
     *      I18n.setLanguage(en);
     *      I18n.setLanguage(es-VE);
     *      I18n.setLanguage(es-ES);
     * @param language 
     */
    public static void setLanguage(String language) {
        LANGUAGE = Locale.forLanguageTag(language);
        bundle = ResourceBundle.getBundle(LANG_PATH, LANGUAGE);
    }

    public static String getLangPath() {
        return LANG_PATH;
    }

    public static void setLangPath(String langPath) {
        LANG_PATH = langPath;
        bundle = ResourceBundle.getBundle(LANG_PATH, LANGUAGE);
    }
}
