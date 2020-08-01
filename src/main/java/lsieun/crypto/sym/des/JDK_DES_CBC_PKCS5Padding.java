package lsieun.crypto.sym.des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

public class JDK_DES_CBC_PKCS5Padding {
    public static byte[] encrypt(byte[] plain_text_bytes, byte[] key_bytes, byte[] iv_bytes) {
        try {
            DESKeySpec desKey = new DESKeySpec(key_bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKey);

            AlgorithmParameterSpec algParameters = new IvParameterSpec(iv_bytes);

            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algParameters);
            return cipher.doFinal(plain_text_bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] decrypt(byte[] cipher_text_bytes, byte[] key_bytes, byte[] iv_bytes) {
        try {
            DESKeySpec desKey = new DESKeySpec(key_bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKey);

            AlgorithmParameterSpec algParameters = new IvParameterSpec(iv_bytes);

            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algParameters);
            return cipher.doFinal(cipher_text_bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
