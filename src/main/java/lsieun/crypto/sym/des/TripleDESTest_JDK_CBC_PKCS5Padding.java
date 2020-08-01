package lsieun.crypto.sym.des;

import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Formatter;

public class TripleDESTest_JDK_CBC_PKCS5Padding {
    public static final String FORMAT = "%20s: %s%n";

    public static void main(String[] args) {
        byte[] input = TripleDESSample.input;
        byte[] key = TripleDESSample.key;
        byte[] iv = TripleDESSample.iv;
        byte[] output = TripleDESSample.output_cbc_pkcs5padding;

        // encrypt and decrypt
        byte[] encrypted_bytes = JDK_TripleDES_CBC_PKCS5Padding.encrypt(input, key, iv);
        byte[] decrypted_bytes = JDK_TripleDES_CBC_PKCS5Padding.decrypt(encrypted_bytes, key, iv);

        // output
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format(FORMAT, "Equals", Arrays.equals(output, encrypted_bytes));
        fm.format(FORMAT, "original bytes", HexUtils.toHex(input));
        fm.format(FORMAT, "encrypted bytes", HexUtils.toHex(encrypted_bytes));
        fm.format(FORMAT, "decrypted bytes", HexUtils.toHex(decrypted_bytes));
        System.out.println(sb);
    }
}
