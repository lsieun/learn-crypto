package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.List;

@SuppressWarnings("Duplicates")
public class C_Msg_03_Substitution_SBox {
    public static void main(String[] args) {
        // (1) get sub key
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        List<byte[]> sub_key_48_bit_list = DESKey.get_sub_keys(key_64_bit_bytes);
        byte[] sub_key_48_bit_bytes = sub_key_48_bit_list.get(0);

        // (2) get message right 32 bit
        byte[] msg_64_bit_bytes = {'c', 'a', 'f', 'e', 'b', 'a', 'b', 'e'};
        byte[] left_32_bit = DESMsg.get_left_part(msg_64_bit_bytes);
        byte[] right_32_bit = DESMsg.get_right_part(msg_64_bit_bytes);

        // (3) expansion from 32 bit to 48 bit
        byte[] expansion_48_bit_bytes = DESMsg.expansion_from_32_to_48_bit_bytes(right_32_bit);

        // (4) xor
        byte[] xor_48_bit_bytes = DESUtils.xor(expansion_48_bit_bytes, sub_key_48_bit_bytes, 6);

        // (5) substitution
        byte[] substitution_32_bit_bytes = DESMsg.sbox_from_48_to_32_bit_bytes(xor_48_bit_bytes);

        System.out.println(ByteUtils.toBinary(expansion_48_bit_bytes));
        System.out.println(ByteUtils.toBinary(sub_key_48_bit_bytes));
        System.out.println(ByteUtils.toBinary(xor_48_bit_bytes));
        System.out.println(ByteUtils.toBinary(substitution_32_bit_bytes));
    }
}
