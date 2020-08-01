package lsieun.crypto.sym.rc4;

import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;

public class RC4Test {
    public static void main(String[] args) {
        byte[] input = "The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8);
        byte[] key = "password".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted_bytes = RC4Utils.rc4_operate(input, key);
        System.out.println(HexUtils.toHex(encrypted_bytes));

        byte[] decrypted_bytes = RC4Utils.rc4_operate(encrypted_bytes, key);
        System.out.println(HexUtils.toHex(decrypted_bytes));
    }
}
