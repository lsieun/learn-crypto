package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("Duplicates")
public class C_Msg_10_Final {
    public static void main(String[] args) {
        // (1) get sub key
        byte[] key_64_bit_bytes = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        List<byte[]> sub_key_48_bit_list = DESKey.get_sub_keys(key_64_bit_bytes);

        // (2) get message right 32 bit
        byte[] msg_64_bit_bytes = {'c', 'a', 'f', 'e', 'b', 'a', 'b', 'e'};

        // (3) get encrypted message
        byte[] encrypted_msg_64_bit_bytes = get_final_bytes(msg_64_bit_bytes, sub_key_48_bit_list);

        // (4) get reverse sub key list
        List<byte[]> reverse_sub_key_48_bit_list = new ArrayList<>();
        for (int i = 15; i >= 0; i--) {
            byte[] bytes = sub_key_48_bit_list.get(i);
            reverse_sub_key_48_bit_list.add(bytes);
        }

        // (5) get decrypted message
        byte[] decrypted_msg_64_bit_bytes = get_final_bytes(encrypted_msg_64_bit_bytes, reverse_sub_key_48_bit_list);

        System.out.println(ByteUtils.toBinary(encrypted_msg_64_bit_bytes));
        System.out.println(ByteUtils.toBinary(decrypted_msg_64_bit_bytes));
        System.out.println(ByteUtils.toBinary(msg_64_bit_bytes));
    }

    public static byte[] get_final_bytes(byte[] msg_64_bit_bytes, List<byte[]> sub_key_48_bit_list) {
        byte[] encrypted_msg_64_bit_bytes = DESUtils.permute(msg_64_bit_bytes, DESConst.ip_table);

        // (1) 16 rounds
        for (int i = 0; i < 16; i++) {
            byte[] sub_key_48_bit_bytes = sub_key_48_bit_list.get(i);
            byte[] new_msg_64_bit_bytes = one_round(encrypted_msg_64_bit_bytes, sub_key_48_bit_bytes);
            System.arraycopy(new_msg_64_bit_bytes, 0, encrypted_msg_64_bit_bytes, 0, 8);
        }

        // (2) swap
        encrypted_msg_64_bit_bytes = DESMsg.swap(encrypted_msg_64_bit_bytes);

        // (3) permutation
        encrypted_msg_64_bit_bytes = DESUtils.permute(encrypted_msg_64_bit_bytes, DESConst.fp_table);

        return encrypted_msg_64_bit_bytes;
    }

    public static byte[] one_round(byte[] msg_64_bit_bytes, byte[] sub_key_48_bit_bytes) {
        byte[] left_32_bit = DESMsg.get_left_part(msg_64_bit_bytes);
        byte[] right_32_bit = DESMsg.get_right_part(msg_64_bit_bytes);

        // (1) expansion from 32 bit to 48 bit
        byte[] expansion_48_bit_bytes = DESMsg.expansion_from_32_to_48_bit_bytes(right_32_bit);

        // (2) xor
        byte[] xor_48_bit_bytes = DESUtils.xor(expansion_48_bit_bytes, sub_key_48_bit_bytes, 6);

        // (3) substitution
        byte[] substitution_32_bit_bytes = DESMsg.sbox_from_48_to_32_bit_bytes(xor_48_bit_bytes);

        // (4) permutation
        byte[] permutation_32_bit_bytes = DESUtils.permute(substitution_32_bit_bytes, DESConst.p_table);

        // (5) xor
        byte[] xor_32_bit_bytes = DESUtils.xor(permutation_32_bit_bytes, left_32_bit, 4);

        // (6) swap
        byte[] new_msg_64_bit_bytes = DESMsg.combine_32_to_64_bytes(right_32_bit, xor_32_bit_bytes);

        return new_msg_64_bit_bytes;
    }

}
