package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.ArrayList;
import java.util.List;

public class DESMsg {
    public static List<byte[]> process(byte[] content_64_bit_bytes, List<byte[]> sub_key_48_bit_list) {
        byte[] tmp_64_bit_bytes = new byte[8];
        System.arraycopy(content_64_bit_bytes, 0, tmp_64_bit_bytes, 0, 8);

        List<byte[]> list = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            System.out.println("===> " + (i+1));
            byte[] sub_key_48_bit_bytes = sub_key_48_bit_list.get(i);
            byte[] bytes = process(tmp_64_bit_bytes, sub_key_48_bit_bytes);
            list.add(bytes);

            System.arraycopy(bytes, 0, tmp_64_bit_bytes, 0, 8);
            System.out.println("\n\n");
        }
        return list;
    }

    public static byte[] process(byte[] content_64_bit_bytes, byte[] sub_key_48_bit_bytes) {
        byte[] left_32_bit_bytes = get_left_part(content_64_bit_bytes);
        byte[] right_32_bit_bytes = get_right_part(content_64_bit_bytes);

        byte[] right_48_bit_bytes = expansion_from_32_to_48_bit_bytes(right_32_bit_bytes);
        System.out.println("Expansion: \n" + ByteUtils.toBinary(right_48_bit_bytes));
        byte[] xor_48_bit_bytes = DESUtils.xor(right_48_bit_bytes, sub_key_48_bit_bytes, 6);
        System.out.println("Xor with subkey: \n" + ByteUtils.toBinary(xor_48_bit_bytes));

        byte[] substitution_32_bit_bytes = sbox_from_48_to_32_bit_bytes(xor_48_bit_bytes);
        System.out.println("After Sbox: \n" + ByteUtils.toBinary(substitution_32_bit_bytes));

        byte[] permuted_32_bit_bytes = DESUtils.permute(substitution_32_bit_bytes, DESConst.p_table);
        System.out.println("After Permutation: \n" + ByteUtils.toBinary(permuted_32_bit_bytes));

        byte[] new_right_32_bit_bytes = DESUtils.xor(permuted_32_bit_bytes, left_32_bit_bytes, 4);

        byte[] new_bytes = combine_32_to_64_bytes(right_32_bit_bytes, new_right_32_bit_bytes);
        System.out.println("After Round: \n" + ByteUtils.toBinary(new_bytes));
        return new_bytes;
    }

    public static byte[] swap(byte[] content_64_bit_bytes) {
        byte[] left_32_bit_bytes = get_left_part(content_64_bit_bytes);
        byte[] right_32_bit_bytes = get_right_part(content_64_bit_bytes);
        return combine_32_to_64_bytes(right_32_bit_bytes, left_32_bit_bytes);
    }

    public static byte[] combine_32_to_64_bytes(byte[] left_32_bit_bytes, byte[] right_32_bit_bytes) {
        byte[] bytes = new byte[8];
        bytes[0] = left_32_bit_bytes[0];
        bytes[1] = left_32_bit_bytes[1];
        bytes[2] = left_32_bit_bytes[2];
        bytes[3] = left_32_bit_bytes[3];
        bytes[4] = right_32_bit_bytes[0];
        bytes[5] = right_32_bit_bytes[1];
        bytes[6] = right_32_bit_bytes[2];
        bytes[7] = right_32_bit_bytes[3];
        return bytes;
    }

    public static byte[] sbox_from_48_to_32_bit_bytes(byte[] xor_48_bit_bytes) {
        return DESUtils.get_substitution(xor_48_bit_bytes);
    }

    public static byte[] expansion_from_32_to_48_bit_bytes(byte[] right_32_bit_bytes) {
        return DESUtils.permute(right_32_bit_bytes, DESConst.expansion_table);
    }

    public static byte[] get_left_part(final byte[] content_64_bit_bytes) {
        byte[] bytes = new byte[4];
        System.arraycopy(content_64_bit_bytes, 0, bytes, 0, 4);
        return bytes;
    }

    public static byte[] get_right_part(final byte[] content_64_bit_bytes) {
        byte[] bytes = new byte[4];
        System.arraycopy(content_64_bit_bytes, 4, bytes, 0, 4);
        return bytes;
    }
}
