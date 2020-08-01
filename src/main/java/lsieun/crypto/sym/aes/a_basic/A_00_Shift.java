package lsieun.crypto.sym.aes.a_basic;

import lsieun.utils.ByteUtils;

public class A_00_Shift {
    public static void main(String[] args) {
        for (byte b = 0x01; b != 0; b <<= 1) {
            System.out.println(ByteUtils.toBinary(b));
        }
    }
}
