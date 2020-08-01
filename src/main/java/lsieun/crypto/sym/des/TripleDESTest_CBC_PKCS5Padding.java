package lsieun.crypto.sym.des;

import lsieun.crypto.sym.modes.CBCUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexUtils;
import lsieun.utils.PaddingUtils;

import java.util.Arrays;
import java.util.Formatter;

public class TripleDESTest_CBC_PKCS5Padding {
    public static final String FORMAT = "%20s: %s%n";

    public static void main(String[] args) {
        byte[] input = TripleDESSample.input;
        byte[] key = TripleDESSample.key;
        byte[] iv = TripleDESSample.iv;
        byte[] output = TripleDESSample.output_cbc_pkcs5padding;

        // add padding
        byte[] padded_input = PaddingUtils.add_pkcs5_padding(input, 8);

        // encrypt and decrypt
        int block_size = DESConst.DES_BLOCK_SIZE;
        byte[] encrypted_bytes = CBCUtils.cbc_encrypt(padded_input, key, iv, block_size, TripleDESUtils::des_block_encrypt);
        byte[] decrypted_bytes = CBCUtils.cbc_decrypt(encrypted_bytes, key, iv, block_size, TripleDESUtils::des_block_decrypt);

        // remove padding
        byte[] pad_removed_bytes = PaddingUtils.remove_pkcs5_padding(decrypted_bytes);

        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format(FORMAT, "Equals", Arrays.equals(output, encrypted_bytes));
        fm.format(FORMAT, "original bytes", HexUtils.toHex(input));
        fm.format(FORMAT, "encrypted bytes", HexUtils.toHex(encrypted_bytes));
        fm.format(FORMAT, "decrypted bytes", HexUtils.toHex(decrypted_bytes));
        fm.format(FORMAT, "pad removed bytes", HexUtils.toHex(pad_removed_bytes));
        System.out.println(sb);
    }
}
