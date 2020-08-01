package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.List;

public class Test_01_KeySchedule_128 {
    public static void main(String[] args) {
        String cipher_key = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
        byte[] key_bytes = HexUtils.parse(cipher_key, HexFormat.FORMAT_FF_SPACE_FF);

        List<byte[]> bytes_list = AESUtils.compute_key_schedule(key_bytes);
        for (int i = 0; i < bytes_list.size(); i++) {
            byte[] bytes = bytes_list.get(i);
            String line = String.format("%02d: %s", i, HexUtils.toHex(bytes));
            System.out.println(line);
        }
    }
}
