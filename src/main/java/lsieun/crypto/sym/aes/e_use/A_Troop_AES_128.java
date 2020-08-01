package lsieun.crypto.sym.aes.e_use;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;

public class A_Troop_AES_128 {
    public static void main(String[] args) {
        String plain_text = "Withdraw troops from Bunker Hill and move them to Normandy beach";
        String key_text = "passwordsecurity";
        String iv_text = "initializationvc";

        byte[] plain_text_bytes = plain_text.getBytes(StandardCharsets.UTF_8);
        byte[] key_bytes = key_text.getBytes(StandardCharsets.UTF_8);
        byte[] iv_bytes = iv_text.getBytes(StandardCharsets.UTF_8);

        int length = plain_text_bytes.length;
        byte[] encrypted_bytes = new byte[length];
        AESUtils.aes_128_encrypt(plain_text_bytes, length, encrypted_bytes, iv_bytes, key_bytes);
        System.out.println(HexUtils.toHex(encrypted_bytes));
    }
}
