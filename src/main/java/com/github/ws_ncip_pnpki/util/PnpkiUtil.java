package com.github.ws_ncip_pnpki.util;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class PnpkiUtil {

    public static CertData loadPkcs12(File pkcs12File, String password)throws Exception{
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try(FileInputStream fis = new FileInputStream(pkcs12File)){
            ks.load(fis, password.toCharArray());
        }

        String alias = null;
        Enumeration<String> aliases = ks.aliases();
        while(aliases.hasMoreElements()){
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                alias = a; break;
            }
        }
        if(alias == null) throw new Exception("No Key entry found in keystore");
        PrivateKey key = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        CertData cd = new CertData();
        cd.privateKey = key; cd.chain = chain;
        return cd;
    }

}
