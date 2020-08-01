package lsieun.crypto.sym.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JDK_AES {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";

    public static byte[] encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted_bytes = cipher.doFinal(value.getBytes());
            return encrypted_bytes;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(byte[] encrypted_bytes) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(encrypted_bytes);

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        String originalString = "password";
        System.out.println("Original String to encrypt - " + originalString);
        byte[] encrypted_bytes = encrypt(originalString);
        System.out.println("Encrypted String - " + encrypted_bytes);
        String decryptedString = decrypt(encrypted_bytes);
        System.out.println("After decryption - " + decryptedString);
    }
}
