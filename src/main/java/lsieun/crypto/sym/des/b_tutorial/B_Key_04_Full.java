package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.List;

@SuppressWarnings("Duplicates")
public class B_Key_04_Full {
    public static void main(String[] args) {
        // (1) 64 bit
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        System.out.println(ByteUtils.toBinary(key_64_bit_bytes));

        // (2) 64 bit --> 56 bit
        byte[] key_56_bit_bytes = DESKey.from_64_to_56_bit_key_bytes(key_64_bit_bytes);
        System.out.println(ByteUtils.toBinary(key_56_bit_bytes));

        // (3) 56 bit --> 56 bit list
        List<byte[]> sub_key_56_bit_list = DESKey.roll_56_bit_key_bytes(key_56_bit_bytes, OperationType.ENCRYPT);

        // (4) 56 bit list --> 48 bit list
        List<byte[]> sub_key_48_bit_list = DESKey.from_56_to_48_bit_sub_key_list(sub_key_56_bit_list);

        // (5) display
        for (int i = 0; i < 16; i++) {
            byte[] bytes = sub_key_48_bit_list.get(i);
            System.out.println(ByteUtils.toBinary(bytes));
        }
    }
}
