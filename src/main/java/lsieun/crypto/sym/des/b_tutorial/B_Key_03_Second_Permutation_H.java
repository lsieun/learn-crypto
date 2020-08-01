package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("Duplicates")
public class B_Key_03_Second_Permutation_H {
    public static void main(String[] args) {
        // (1) 64 bit
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

        // (2) 64 bit --> 56 bit
        byte[] key_56_bit_bytes = DESKey.from_64_to_56_bit_key_bytes(key_64_bit_bytes);

        // (3) 56 bit --> 56 bit list
        List<byte[]> sub_key_56_bit_bytes_list = DESKey.roll_56_bit_key_bytes(key_56_bit_bytes, OperationType.ENCRYPT);

        // (4) 56 bit list --> 48 bit list
        List<byte[]> sub_key_48_bit_list = new ArrayList<>();
        for (byte[] bytes_56_bit : sub_key_56_bit_bytes_list) {
            byte[] bytes_48_bit = DESKey.from_56_to_48_bit_key_bytes(bytes_56_bit);
            sub_key_48_bit_list.add(bytes_48_bit);
        }

        // (5) display
        for (int i = 0; i < sub_key_48_bit_list.size(); i++) {
            byte[] bytes = sub_key_48_bit_list.get(i);
            String line = String.format("%02d: %s", (i+1), ByteUtils.toBinary(bytes));
            System.out.println(line);
        }
    }
}
