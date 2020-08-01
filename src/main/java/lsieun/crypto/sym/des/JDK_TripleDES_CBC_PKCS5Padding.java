package lsieun.crypto.sym.des;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

public class JDK_TripleDES_CBC_PKCS5Padding {
    public static byte[] encrypt(byte[] plain_text_bytes, byte[] key_bytes, byte[] iv_bytes) {
        try {
            DESedeKeySpec desKey = new DESedeKeySpec(key_bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(desKey);

            AlgorithmParameterSpec algParameters = new IvParameterSpec(iv_bytes);

            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algParameters);
            return cipher.doFinal(plain_text_bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] decrypt(byte[] cipher_text_bytes, byte[] key_bytes, byte[] iv_bytes) {
        try {
            DESedeKeySpec desKey = new DESedeKeySpec(key_bytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(desKey);

            AlgorithmParameterSpec algParameters = new IvParameterSpec(iv_bytes);

            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algParameters);
            return cipher.doFinal(cipher_text_bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
