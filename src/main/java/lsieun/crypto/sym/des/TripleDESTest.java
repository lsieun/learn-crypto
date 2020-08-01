package lsieun.crypto.sym.des;

import lsieun.crypto.sym.modes.ECBUtils;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TripleDESTest {
    public static void main(String[] args) {
        byte[] input = "abcdefgh".getBytes(StandardCharsets.UTF_8);
        byte[] key = "twentyfourcharacterinput".getBytes(StandardCharsets.UTF_8);
        byte[] iv = "initialz".getBytes(StandardCharsets.UTF_8);

        byte[] expected_cipher = {
                (byte)0xc0, (byte)0xc4, (byte)0x8b, (byte)0xc4,
                (byte)0x7e, (byte)0x87, (byte)0xce, (byte)0x17
        };

        int block_size = DESConst.DES_BLOCK_SIZE;
        byte[] encrypted_bytes = ECBUtils.ecb_encrypt(input, key, block_size, TripleDESUtils::des_block_encrypt);

        byte[] decrypted_bytes = ECBUtils.ecb_decrypt(encrypted_bytes, key, block_size, TripleDESUtils::des_block_decrypt);

        String format = "%15s: %s";

        System.out.println(Arrays.equals(expected_cipher, encrypted_bytes));
        System.out.println(String.format(format, "encrypted bytes", HexUtils.toHex(encrypted_bytes)));
        System.out.println(String.format(format, "decrypted bytes", HexUtils.toHex(decrypted_bytes)));
        System.out.println(String.format(format, "original bytes", HexUtils.toHex(input)));
    }
}
