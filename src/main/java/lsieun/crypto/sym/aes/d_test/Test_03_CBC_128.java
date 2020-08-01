package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESConst;
import lsieun.crypto.sym.aes.AESExample;
import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.PaddingUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Test_03_CBC_128 {
    public static void main(String[] args) throws Exception {

        byte[] plain_text_bytes = "anything you can think of你在做什么呢?同学".getBytes(StandardCharsets.UTF_8);
        byte[] padded_plain_text_bytes = PaddingUtils.add_pkcs5_padding(plain_text_bytes, AESConst.AES_BLOCK_SIZE);
        int padded_plain_text_len = padded_plain_text_bytes.length;

        byte[] encrypted_bytes = new byte[padded_plain_text_len];
        AESUtils.aes_128_encrypt(padded_plain_text_bytes, padded_plain_text_len, encrypted_bytes, AESExample.iv_128_bit_bytes, AESExample.key_128_bit_bytes);

        byte[] decrypted_bytes = new byte[padded_plain_text_len];
        AESUtils.aes_128_decrypt(encrypted_bytes, encrypted_bytes.length, decrypted_bytes, AESExample.iv_128_bit_bytes, AESExample.key_128_bit_bytes);

        byte[] removed_decrypted_bytes = PaddingUtils.remove_pkcs5_padding(decrypted_bytes);
        System.out.println(new String(removed_decrypted_bytes, StandardCharsets.UTF_8));

        byte[] encrypted_bytes2 = encrypt(plain_text_bytes, AESExample.key_128_bit_bytes, AESExample.iv_128_bit_bytes);
        byte[] decrypted_bytes2 = decrypt(encrypted_bytes2, AESExample.key_128_bit_bytes, AESExample.iv_128_bit_bytes);
        System.out.println(Arrays.equals(encrypted_bytes, encrypted_bytes2));
        System.out.println(Arrays.equals(removed_decrypted_bytes, decrypted_bytes2));
    }

    public static byte[] encrypt(byte[] plain_text_bytes, byte[] key_bytes, byte[] iv_bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key_bytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv_bytes);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] cipher_text_bytes = cipher.doFinal(plain_text_bytes);
        return cipher_text_bytes;
    }

    public static byte[] decrypt(byte[] cipher_text_bytes, byte[] key_bytes, byte[] iv_bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key_bytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv_bytes);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decrypted_bytes = cipher.doFinal(cipher_text_bytes);
        return decrypted_bytes;
    }
}
