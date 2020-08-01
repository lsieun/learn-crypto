package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

@SuppressWarnings("Duplicates")
public class Test_02_Encryption_128 {
    public static void main(String[] args) {
//        byte[] key_bytes = CipherUtils.from_hex_to_bytes("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", " ");
//        byte[] plain_text_bytes = CipherUtils.from_hex_to_bytes("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34", " ");

        byte[] key_bytes = HexUtils.parse("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", HexFormat.FORMAT_FF_SPACE_FF);
        byte[] plain_text_bytes = HexUtils.parse("00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff", HexFormat.FORMAT_FF_SPACE_FF);

        byte[] encrypted_bytes = AESUtils.aes_block_encrypt(plain_text_bytes, key_bytes);
//        System.out.println(ByteUtils.toHex(encrypted_bytes));
        System.out.println("==============================");

        byte[] decrypted_bytes = AESUtils.aes_block_decrypt(encrypted_bytes, key_bytes);
//        System.out.println(ByteUtils.toHex(decrypted_bytes));
//        System.out.println(ByteUtils.toHex(plain_text_bytes));
    }
}
