package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

@SuppressWarnings("Duplicates")
public class Test_02_Encryption_192 {
    public static void main(String[] args) {
        byte[] key_bytes = HexUtils.parse("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17", HexFormat.FORMAT_FF_SPACE_FF);
        byte[] plain_text_bytes = HexUtils.parse("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", HexFormat.FORMAT_FF_SPACE_FF);

        byte[] encrypted_bytes = AESUtils.aes_block_encrypt(plain_text_bytes, key_bytes);
        System.out.println(HexUtils.toHex(encrypted_bytes));
        System.out.println("==============================");

        byte[] decrypted_bytes = AESUtils.aes_block_decrypt(encrypted_bytes, key_bytes);
        System.out.println(HexUtils.toHex(decrypted_bytes));
        System.out.println(HexUtils.toHex(plain_text_bytes));
    }
}
