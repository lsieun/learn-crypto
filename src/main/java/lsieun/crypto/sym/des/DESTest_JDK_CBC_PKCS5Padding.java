package lsieun.crypto.sym.des;

import lsieun.utils.HexUtils;

import java.util.Arrays;

public class DESTest_JDK_CBC_PKCS5Padding {
    public static void main(String[] args) {
        byte[] input = DESSample.input;
        byte[] key = DESSample.key;
        byte[] iv = DESSample.iv;
        byte[] output = DESSample.output_cbc;

        byte[] encrypted_bytes = JDK_DES_CBC_PKCS5Padding.encrypt(input, key, iv);
        byte[] decrypted_bytes = JDK_DES_CBC_PKCS5Padding.decrypt(encrypted_bytes, key, iv);

        System.out.println(Arrays.equals(output, encrypted_bytes));
        System.out.println(HexUtils.toHex(encrypted_bytes));
        System.out.println(HexUtils.toHex(decrypted_bytes));
        System.out.println(HexUtils.toHex(input));
    }
}
