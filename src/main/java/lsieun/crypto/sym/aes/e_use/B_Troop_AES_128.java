package lsieun.crypto.sym.aes.e_use;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;

public class B_Troop_AES_128 {
    public static void main(String[] args) {
        String cipher_text = "c99a87a32c57b80de43c26f762556a76bfb3040f7fc38e112d3ffddf4a5cb703";
        String key_text = "passwordsecurity";
        String iv_text = "initializationvc";

        byte[] cipher_text_bytes = HexUtils.parse(cipher_text, HexFormat.FORMAT_FF_FF);
        byte[] key_bytes = key_text.getBytes(StandardCharsets.UTF_8);
        byte[] iv_bytes = iv_text.getBytes(StandardCharsets.UTF_8);

        int length = cipher_text_bytes.length;

        byte[] decrypted_bytes = new byte[length];
        AESUtils.aes_128_decrypt(cipher_text_bytes, length, decrypted_bytes, iv_bytes, key_bytes);
        System.out.println(new String(decrypted_bytes, StandardCharsets.UTF_8));
    }
}
