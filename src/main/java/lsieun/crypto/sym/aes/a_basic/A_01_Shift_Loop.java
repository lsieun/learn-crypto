package lsieun.crypto.sym.aes.a_basic;

import lsieun.utils.ByteUtils;

import java.util.Random;

public class A_01_Shift_Loop {
    private static final String FORMAT = "%02d: %s";

    public static void main(String[] args) {
        Random rand = new Random();
        byte b = (byte) rand.nextInt();
        String first_line = String.format(FORMAT, 0, ByteUtils.toBinary(b));
        System.out.println(first_line);

        for (int i = 0; i < 8; i++) {
            b = left_shift(b);
            String line = String.format(FORMAT, (i + 1), ByteUtils.toBinary(b));
            System.out.println(line);
        }

    }

    public static byte left_shift(byte b) {
        int val = b & 0xFF;
        int result = (val << 1) | ((val & 0x80) >> 7);
        return (byte) result;
    }
}
