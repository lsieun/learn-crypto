package lsieun.crypto.sym.modes;

import lsieun.crypto.sym.BlockOperation;
import lsieun.crypto.sym.aes.AESUtils;
import lsieun.crypto.sym.sample.AES128Sample;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CTRUtils {

    public static byte[] operate(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation encrypt_algorithm) {
        int input_length = input.length;
        int iv_length = iv.length;
        if (iv_length != block_size) {
            throw new IllegalArgumentException("iv's length is not valid");
        }

        byte[] output = new byte[input_length];
        byte[] input_block = new byte[block_size];
        int times = input_length / block_size;
        int remain = input_length % block_size;

        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);
            byte[] encrypted_bytes = encrypt_algorithm.block_operate(iv, key);
            byte[] xor_bytes = ByteUtils.xor(input_block, encrypted_bytes, block_size);

            System.arraycopy(xor_bytes, 0, output, i * block_size, block_size);
            iv = ByteUtils.add_one(iv, 4);
        }

        if (remain > 0) {
            System.arraycopy(input, times * block_size, input_block, 0, remain);
            byte[] encrypted_bytes = encrypt_algorithm.block_operate(iv, key);
            byte[] xor_bytes = ByteUtils.xor(input_block, encrypted_bytes, block_size);
            System.arraycopy(xor_bytes, 0, output, times * block_size, remain);
        }
        return output;
    }

    public static void main(String[] args) {
//        test_128();
        byte[] bytes = {0x01, (byte) 0xF4};
        int val = ByteUtils.toInt(bytes);
        System.out.println(val);
    }

    public static void test_128() {
        byte[] plain_text_bytes = Arrays.copyOf(AES128Sample.plain_text_bytes, AES128Sample.plain_text_bytes.length);
        byte[] key_bytes = Arrays.copyOf(AES128Sample.key_bytes, AES128Sample.key_bytes.length);
        byte[] nonce_bytes = Arrays.copyOf(AES128Sample.nonce_bytes, AES128Sample.nonce_bytes.length);
        byte[] encrypt_bytes = CTRUtils.operate(plain_text_bytes, key_bytes, nonce_bytes, 16, AESUtils::aes_block_encrypt);
        System.out.println(HexUtils.format(encrypt_bytes, " ", 16));
        System.out.println();

        nonce_bytes = Arrays.copyOf(AES128Sample.nonce_bytes, AES128Sample.nonce_bytes.length);
        byte[] cipher_text_bytes = Arrays.copyOf(AES128Sample.ctr_cipher_text_bytes, AES128Sample.ctr_cipher_text_bytes.length);
        byte[] decrypt_bytes = CTRUtils.operate(cipher_text_bytes, key_bytes, nonce_bytes, 16, AESUtils::aes_block_encrypt);
        System.out.println(HexUtils.format(decrypt_bytes, " ", 16));
    }

    public static void test2() {
        String str = "Hello, World!!";
        byte[] plain_text_bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] key_bytes = HexUtils.parse("404142434445464748494a4b4c4d4e4f", HexFormat.FORMAT_FF_FF);
        byte[] nonce_bytes = new byte[]{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
        byte[] iv_bytes = new byte[16];
        System.arraycopy(nonce_bytes, 0, iv_bytes, 0, nonce_bytes.length);

        byte[] encrypted_bytes = CTRUtils.operate(plain_text_bytes, key_bytes, iv_bytes, 16, AESUtils::aes_block_encrypt);
        System.out.println(HexUtils.format(encrypted_bytes, HexFormat.FORMAT_FF_SPACE_FF));
    }
}
