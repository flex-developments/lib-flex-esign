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

package flex.eSign.test;

import flex.eSign.helpers.AlgorithmsHelper;
import flex.eSign.helpers.CertificateHelper;
import flex.helpers.SystemHelper;
import flex.helpers.exceptions.SystemHelperException;
import flex.pkikeys.PKIKeys;
import flex.pkikeys.Repositories.AbstractRepositoryConfiguration;
import flex.pkikeys.Repositories.RepositoryConfigurationFactory;
import flex.pkikeys.Repositories.RepositoriesWhiteList;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * TestsResources
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments en gmail
 * @author Ing. Yessica De Ascencao - yessicadeascencao en gmail
 * @version 1.0
 */
public class TestsResources {
    public static String resourcesPath = System.getProperty("user.home") + File.separator + "resources" + File.separator;
    
    public static List<String> getNTPServers() throws Exception {
        List<String> ntpServers = new ArrayList<>();
        ntpServers.add("tecnica.lab");
        ntpServers.add("servicios.lab");
        return ntpServers;
    }
    
    public static List<X509Certificate> getAuthorities() throws Exception {
        InputStream reader = new FileInputStream(resourcesPath + "CadenaDual.pem");
        return CertificateHelper.loadPEMCertificate(reader);
    }
    
    public static String getEncodedRepositoryConfiguration() throws SystemHelperException {
        if(SystemHelper.isWindows())
            return "dHlwZT1QS0NTMTIKcGF0aD1DOlxVc2Vyc1xBUkFHT05ccmVzb3VyY2VzXGMyLTIucDEy";
        else 
            //return "dHlwZT1QS0NTMTIKcGF0aD0vaG9tZS9mbG9wZXovcmVzb3VyY2VzL2MxLTIucDEy";
            return "dHlwZT1QS0NTMTEKbmFtZT1PdHJvCnBhdGg9L29wdC9lcGFzczMwMDBfUFNDL3JlZGlzdC9saWJz\n" +
                    "aHV0dGxlX3AxMXYyMjBfcHNjLnNv";
    }
    
    public static PKIKeys getKeys(
            boolean loadRepositoryConfiguration, 
            boolean verifyRepositoryIntegrity,
            boolean loadFromGUI
    ) throws Exception {
        PKIKeys clientKeys = null;
        String conf = null;
        
        if(loadRepositoryConfiguration) conf = getEncodedRepositoryConfiguration();
        
        if(conf != null) {
            AbstractRepositoryConfiguration repositoryConfiguration = RepositoryConfigurationFactory.getInstanceFromEncodedConf(conf);
            clientKeys = new PKIKeys(repositoryConfiguration);
            System.out.println("Configuration inicial <" + clientKeys.getRepositoryConfiguration().getConfigurationEncode() + ">");
            
        } else {
            clientKeys = new PKIKeys();
        }
        
        if(loadFromGUI) clientKeys.loadFromGUI();
        
        else clientKeys.loadFromConsole();
        
        if (verifyRepositoryIntegrity) {
            RepositoriesWhiteList whiteList = new RepositoriesWhiteList(AlgorithmsHelper.HASH_ALGORITHM_SHA256);
            //c1-2.p12
            whiteList.add("788a48e355ec3be4cbef23a268e493ac00c7244f4d04077c899d1da1e889de7e");
            //c2-2.p12
            whiteList.add("69958331515f639e690725026d06e2fcc5263091b1987f1e09a9a05369d69585");
            clientKeys.setVerifyRepositoryIntegrity(verifyRepositoryIntegrity);
            clientKeys.setWitheListRepositories(whiteList);
        }
        
        //Cargar y retornar las llaves
        clientKeys.loadKeys(null);
        return clientKeys;
    }
    
//    private static byte[] getBytes(InputStream is) throws IOException {
//        int len;
//        int size = 1024;
//        byte[] buf;
//
//        if (is instanceof ByteArrayInputStream) {
//          size = is.available();
//          buf = new byte[size];
//          len = is.read(buf, 0, size);
//        } else {
//          ByteArrayOutputStream bos = new ByteArrayOutputStream();
//          buf = new byte[size];
//          while ((len = is.read(buf, 0, size)) != -1)
//            bos.write(buf, 0, len);
//          buf = bos.toByteArray();
//        }
//        return buf;
//    }
}