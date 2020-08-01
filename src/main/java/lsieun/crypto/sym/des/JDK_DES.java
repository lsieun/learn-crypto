package lsieun.crypto.sym.des;

import lsieun.utils.HexUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;

/**
 * DES加密介绍
 * DES是一种对称加密算法，所谓对称加密算法即：加密和解密使用相同密钥的算法。DES加密算法出自IBM的研究，
 * 后来被美国政府正式采用，之后开始广泛流传，但是近些年使用越来越少，因为DES使用56位密钥，以现代计算能力，
 * 24小时内即可被破解。虽然如此，在某些简单应用中，我们还是可以使用DES加密算法，本文简单讲解DES的JAVA实现
 * 。
 * 注意：DES加密和解密过程中，密钥长度都必须是8的倍数。
 * 在这里，默认使用了pkcs5填充数据。
 */
public class JDK_DES {
    public static byte[] encrypt(byte[] plain_text_bytes, byte[] key_bytes) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(key_bytes);
            //创建一个密匙工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKey);
            //Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES");
            //用密匙初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);
            //现在，获取数据并加密
            //正式执行加密操作
            return cipher.doFinal(plain_text_bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] decrypt(byte[] encrypted_bytes, byte[] key_bytes) {
        try {
            // DES算法要求有一个可信任的随机数源
            SecureRandom random = new SecureRandom();
            // 创建一个DESKeySpec对象
            DESKeySpec desKey = new DESKeySpec(key_bytes);
            // 创建一个密匙工厂
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // 将DESKeySpec对象转换成SecretKey对象
            SecretKey secretKey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成解密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密匙初始化Cipher对象
            cipher.init(Cipher.DECRYPT_MODE, secretKey, random);
            // 真正开始解密操作
            return cipher.doFinal(encrypted_bytes);
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void main(String args[]) {
        // 第1步，准备输入
        byte[] plain_text_bytes = DESSample.input;
        byte[] key_bytes = DESSample.key;

        // 第2步，加密和解密
        byte[] encrypted_bytes = encrypt(plain_text_bytes, key_bytes);
        byte[] decrypted_bytes = decrypt(encrypted_bytes, key_bytes);

        // 第3步，打印输出
        System.out.println("加密前：" + HexUtils.toHex(plain_text_bytes));
        System.out.println("加密后：" + HexUtils.toHex(encrypted_bytes));
        System.out.println("解密后：" + HexUtils.toHex(decrypted_bytes));
    }
}
