package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.List;

public class Test_01_KeySchedule_256 {
    public static void main(String[] args) {
        String cipher_key = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4";
        byte[] key_bytes = HexUtils.parse(cipher_key, HexFormat.FORMAT_FF_SPACE_FF);

        List<byte[]> bytes_list = AESUtils.compute_key_schedule(key_bytes);
        for (int i = 0; i < bytes_list.size(); i++) {
            byte[] bytes = bytes_list.get(i);
            String line = String.format("%02d: %s", i, HexUtils.toHex(bytes));
            System.out.println(line);
        }
    }
}
