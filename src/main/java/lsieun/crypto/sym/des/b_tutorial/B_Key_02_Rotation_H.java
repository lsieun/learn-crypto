package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.List;

@SuppressWarnings("Duplicates")
public class B_Key_02_Rotation_H {
    public static void main(String[] args) {
        // (1) 64 bit
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        System.out.println("64 bit key: " + ByteUtils.toBinary(key_64_bit_bytes));

        // (2) 64 bit --> 56 bit
        byte[] key_56_bit_bytes = DESKey.from_64_to_56_bit_key_bytes(key_64_bit_bytes);
        System.out.println("56 bit key: " + ByteUtils.toBinary(key_56_bit_bytes));

        // (3) 56 bit --> 56 bit list
        List<byte[]> sub_key_56_bit_bytes_list = DESKey.roll_56_bit_key_bytes(key_56_bit_bytes, OperationType.ENCRYPT);

        // (4) display
        for (int i = 0; i < sub_key_56_bit_bytes_list.size(); i++) {
            byte[] bytes = sub_key_56_bit_bytes_list.get(i);
            String line = String.format("%02d: %s", (i + 1), ByteUtils.toBinary(bytes));
            System.out.println(line);
        }
    }
}
