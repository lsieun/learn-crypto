package lsieun.crypto.hash.md5.basic;

import lsieun.crypto.hash.md5.MD5Const;

public class RoundConstant {
    private static final int[] TABLE_T = new int[64];

    static {
        for (int i = 0; i < 64; i++) {
            TABLE_T[i] = (int) (long) ((1L << 32) * Math.abs(Math.sin(i + 1)));
        }
    }

    public static void main(String[] args) {
        for (int i = 0; i < 64; i++) {
            int val1 = TABLE_T[i];
            int val2 = MD5Const.K_array[i];

            if (val1 != val2) {
                System.out.println(String.format("%02d: %s, %s", i, val1, val2));
            }
        }
    }
}
