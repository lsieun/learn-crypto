package lsieun.crypto.sym.des.b_tutorial;

import lsieun.utils.ByteUtils;

@SuppressWarnings("Duplicates")
public class B_Key_01_Initial_Permutation_H {
    public static void main(String[] args) {
        // (1) 64 bit
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        System.out.println("64 bit key: " + ByteUtils.toBinary(key_64_bit_bytes));

        // (2) 64 bit --> 56 bit
        byte[] key_56_bit_bytes = DESKey.from_64_to_56_bit_key_bytes(key_64_bit_bytes);
        System.out.println("56 bit key: " + ByteUtils.toBinary(key_56_bit_bytes));
    }
}
