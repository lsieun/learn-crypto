package lsieun.crypto.sym.des.b_tutorial;

import lsieun.utils.ByteUtils;

@SuppressWarnings("Duplicates")
public class C_Msg_01_Expansion_H {
    public static void main(String[] args) {
        byte[] msg_64_bit_bytes = {'c', 'a', 'f', 'e', 'b', 'a', 'b', 'e'};
        byte[] left_32_bit = DESMsg.get_left_part(msg_64_bit_bytes);
        byte[] right_32_bit = DESMsg.get_right_part(msg_64_bit_bytes);

        byte[] expansion_48_bit_bytes = DESMsg.expansion_from_32_to_48_bit_bytes(right_32_bit);

        System.out.println(ByteUtils.toBinary(msg_64_bit_bytes));
        System.out.println(ByteUtils.toBinary(left_32_bit));
        System.out.println(ByteUtils.toBinary(right_32_bit));
        System.out.println(ByteUtils.toBinary(expansion_48_bit_bytes));
    }
}
