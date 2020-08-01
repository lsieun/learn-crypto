package lsieun.crypto.sym.des;

import lsieun.crypto.sym.modes.CBCUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexUtils;
import lsieun.utils.PaddingUtils;

import java.util.Arrays;

public class DESTest_CBC_PKCS5Padding {
    public static void main(String[] args) {
        byte[] input = DESSample.input;
        byte[] key = DESSample.key;
        byte[] iv = DESSample.iv;
        byte[] output = DESSample.output_cbc;

        // add padding
        byte[] padded_input = PaddingUtils.add_pkcs5_padding(input, 8);

        // encrypt and decrypt
        byte[] encrypted_bytes = CBCUtils.cbc_encrypt(padded_input, key, iv, 8, DESUtils::des_block_encrypt);
        byte[] decrypted_bytes = CBCUtils.cbc_decrypt(encrypted_bytes, key, iv, 8, DESUtils::des_block_decrypt);

        // remove padding
        byte[] pad_removed_bytes = PaddingUtils.remove_pkcs5_padding(decrypted_bytes);

        System.out.println(Arrays.equals(output, encrypted_bytes));
        System.out.println(HexUtils.toHex(encrypted_bytes));
        System.out.println(HexUtils.toHex(decrypted_bytes));
        System.out.println(HexUtils.toHex(pad_removed_bytes));
        System.out.println(HexUtils.toHex(input));
    }
}
