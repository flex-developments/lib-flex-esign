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

package flex.eSign.helpers;

import flex.eSign.i18n.I18n;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ProviderHelper
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class ProviderHelper {
    
    public static Provider getRegCryptographyProvider(Provider cryptographyProvider) throws NullPointerException {
        if (cryptographyProvider != null) {
            if (Security.getProvider(cryptographyProvider.getName()) != null) {
                Security.removeProvider(cryptographyProvider.getName());
                Security.addProvider(cryptographyProvider);
            } else {
                Security.addProvider(cryptographyProvider);
            }
            return cryptographyProvider;
            
        } else {
            throw new NullPointerException(I18n.get(I18n.M_ERROR_NULL_PROVIDER));
        }
    }
    
    public static Provider getRegBouncyCastleCryptographyProvider() {
        return getRegCryptographyProvider(new BouncyCastleProvider());
    }
    
    public static Provider getRegCryptographyProviderOrDefault(Provider cryptographyProvider) {
        try {
            return getRegCryptographyProvider(cryptographyProvider);
            
        } catch (NullPointerException ex) {
            ex = null;
            return getRegBouncyCastleCryptographyProvider();
        }
    }
}
