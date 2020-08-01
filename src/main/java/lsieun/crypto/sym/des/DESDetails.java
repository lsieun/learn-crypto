package lsieun.crypto.sym.des;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Formatter;

public class DESDetails {
    public static final String FORMAT = "%30s: %s%n";

    public static byte[] des_block_operate(byte[] input_64_bit_bytes, byte[] key_64_bit_bytes, OperationType type) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format(FORMAT, "CipherType", type);
        fm.format(FORMAT, "input(64-bit)", HexUtils.toHex(input_64_bit_bytes));

        // Initial permutation
        byte[] content_64_bit_bytes = DESUtils.permute(input_64_bit_bytes, DESConst.ip_table);
        fm.format(FORMAT, "Initial Permutation(64-bit)", HexUtils.toHex(content_64_bit_bytes));

        // Key schedule computation
        byte[] key_56_bit_bytes = DESUtils.permute(key_64_bit_bytes, DESConst.pc1_table);
        fm.format(FORMAT, "key(64-bit)", HexUtils.toHex(key_64_bit_bytes));
        fm.format(FORMAT, "PC-1 key(56-bit)", HexUtils.toHex(key_56_bit_bytes));
        fm.format("%n");

        // (1) 16 rounds
        byte[] current_56_bit_key_bytes = new byte[7];
        System.arraycopy(key_56_bit_bytes, 0, current_56_bit_key_bytes, 0, 7);

        for (int i = 1; i <= 16; i++) {
            fm.format(FORMAT, "Round", i);

            // key
            if (type == OperationType.ENCRYPT) {
                if (i == 1 || i == 2 || i == 9 || i == 16) {
                    DESUtils.rotate_left(current_56_bit_key_bytes);
                } else {
                    DESUtils.rotate_left_twice(current_56_bit_key_bytes);
                }
            }
            fm.format(FORMAT, "key(56-bit)", HexUtils.toHex(current_56_bit_key_bytes));
            byte[] current_48_bit_sub_key_bytes = DESUtils.permute(current_56_bit_key_bytes, DESConst.pc2_table);
            if (type == OperationType.DECRYPT) {
                if (i == 16 || i == 15 || i == 8 || i == 1) {
                    DESUtils.rotate_right(current_56_bit_key_bytes);
                } else {
                    DESUtils.rotate_right_twice(current_56_bit_key_bytes);
                }
            }
            fm.format(FORMAT, "subkey(48-bit)", HexUtils.toHex(current_48_bit_sub_key_bytes));

            // msg
            byte[] left_32_bit_bytes = Arrays.copyOfRange(content_64_bit_bytes, 0, 4);
            byte[] right_32_bit_bytes = Arrays.copyOfRange(content_64_bit_bytes, 4, 8);
            fm.format(FORMAT, "content(64-bit)", HexUtils.toHex(content_64_bit_bytes));
            fm.format(FORMAT, "left content(32-bit)", HexUtils.toHex(left_32_bit_bytes));
            fm.format(FORMAT, "right content(32-bit)", "        " + HexUtils.toHex(right_32_bit_bytes));

            byte[] expansion_48_bit_bytes = DESUtils.permute(right_32_bit_bytes, DESConst.expansion_table);
            fm.format(FORMAT, "right expansion(48-bit)", "        " + HexUtils.toHex(expansion_48_bit_bytes));
            byte[] xor_48_bit_bytes = DESUtils.xor(expansion_48_bit_bytes, current_48_bit_sub_key_bytes, 6);
            fm.format(FORMAT, "right xor subkey(48-bit)", "        " + HexUtils.toHex(xor_48_bit_bytes));
            byte[] substitution_32_bit_bytes = DESUtils.get_substitution(xor_48_bit_bytes);
            fm.format(FORMAT, "substitution(32-bit)", "        " + HexUtils.toHex(substitution_32_bit_bytes));
            byte[] permutation_32_bit_bytes = DESUtils.permute(substitution_32_bit_bytes, DESConst.p_table);
            fm.format(FORMAT, "permutation(32-bit)", "        " + HexUtils.toHex(substitution_32_bit_bytes));
            byte[] xor_32_bit_bytes = DESUtils.xor(permutation_32_bit_bytes, left_32_bit_bytes, 4);
            fm.format(FORMAT, "new right(32-bit)", "        " + HexUtils.toHex(xor_32_bit_bytes));

            // copy
            System.arraycopy(right_32_bit_bytes, 0, content_64_bit_bytes, 0, 4);
            System.arraycopy(xor_32_bit_bytes, 0, content_64_bit_bytes, 4, 4);
            fm.format(FORMAT, "new content(64-bit)", HexUtils.toHex(content_64_bit_bytes));
            fm.format("%n");
        }


        // (2) Swap one last time
        byte[] swap_bytes = new byte[8];
        System.arraycopy(content_64_bit_bytes, 4, swap_bytes, 0, 4);
        System.arraycopy(content_64_bit_bytes, 0, swap_bytes, 4, 4);
        fm.format(FORMAT, "the last swap(64-bit)", HexUtils.toHex(swap_bytes));

        // (3) Final permutation (undo initial permutation)
        byte[] encrypted_64_bit_bytes = DESUtils.permute(swap_bytes, DESConst.fp_table);
        fm.format(FORMAT, "Final Permutation(64-bit)", HexUtils.toHex(encrypted_64_bit_bytes));

        System.out.println(sb.toString());
        return encrypted_64_bit_bytes;
    }
}
