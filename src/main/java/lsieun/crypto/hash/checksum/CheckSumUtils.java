package lsieun.crypto.hash.checksum;

import java.nio.charset.StandardCharsets;

public class CheckSumUtils {
    public static int checksum(byte[] bytes) {
        int total = 0;
        for (byte b : bytes) {
            total += (b & 0xFF);
        }
        return total;
    }

    public static byte[] toByteArray(String msg) {
        return msg.getBytes(StandardCharsets.UTF_8);
    }




}
