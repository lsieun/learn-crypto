package lsieun.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;


public class MyKeyStoreUtil {
    public static KeyStore.Entry getEntry(String keystore, String keystorePass, String keyName, String keyPassword) {

        if (keystore == null || "".equals(keystore)) {
            throw new IllegalArgumentException("keystore can not be blank");
        }
        if (keystorePass == null || "".equals(keystorePass)) {
            throw new IllegalArgumentException("keystorePass can not be blank");
        }
        if (keyName == null || "".equals(keyName)) {
            throw new IllegalArgumentException("keyName can not be blank");
        }
        if (keyPassword == null || "".equals(keyPassword)) {
            throw new IllegalArgumentException("keyPassword can not be blank");
        }

        InputStream keyStoreData = null;
        try {
            keyStoreData = new FileInputStream(keystore);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] keyStorePassword = keystorePass.toCharArray();
            keyStore.load(keyStoreData, keyStorePassword);

            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword.toCharArray());
            KeyStore.Entry entry = keyStore.getEntry(keyName, entryPassword);


            return entry;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        } finally {
            if (keyStoreData != null) {
                try {
                    keyStoreData.close();
                } catch (IOException e) {
                    // do nothing
                }
            }
        }
    }
}
