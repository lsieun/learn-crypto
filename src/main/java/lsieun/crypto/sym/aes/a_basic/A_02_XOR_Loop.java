package lsieun.crypto.sym.aes.a_basic;

import lsieun.utils.ByteUtils;

import java.util.Random;

public class A_02_XOR_Loop {
    private static final String FORMAT = "%02d: %s";

    public static void main(String[] args) {
        Random rand = new Random();
        byte a = (byte) rand.nextInt();
        byte b = (byte) rand.nextInt();

        String first_line = String.format(FORMAT, 0, ByteUtils.toBinary(a));
        System.out.println(first_line);

        String second_line = String.format(FORMAT, 1, ByteUtils.toBinary(b));
        System.out.println(second_line);

        for (int i = 2; i < 12; i++) {
            byte c = (byte) (a ^ b);
            String line = String.format(FORMAT, i, ByteUtils.toBinary(c));
            System.out.println(line);

            a = b;
            b = c;
        }
    }
}
