package lsieun.crypto.sym.des;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

public class DESUtils {

    // region permutation

    /**
     * This does not return a 1 for a 1 bit; it just returns non-zero
     */
    public static int get_bit(byte[] array, int bit) {
        return (array[bit / 8] & 0xFF) & (0x80 >> (bit % 8));
    }

    public static void set_bit(byte[] array, int bit) {
        int val = (array[bit / 8] & 0xFF) | (0x80 >> (bit % 8));
        array[bit / 8] = (byte) val;
    }

    public static void clear_bit(byte[] array, int bit) {
        int val = (array[bit / 8] & 0xFF) & ~(0x80 >> (bit % 8));
        array[bit / 8] = (byte) val;
    }

    /**
     * <p>Implement the permutation functions.</p>
     * NOTE: this assumes that the permutation tables are defined as one-based
     * rather than 0-based arrays, since they’re given that way in the
     * specification.
     */
    public static byte[] permute(byte[] src, int[] permute_table) {
        int bit_size = permute_table.length;
        int byte_size = bit_size / 8;
        byte[] target = new byte[byte_size];

        for (int i = 0; i < bit_size; i++) {
            int pos = permute_table[i] - 1;

            if (get_bit(src, pos) == 0) {
                clear_bit(target, i);
            } else {
                set_bit(target, i);
            }
        }
        return target;
    }

    // endregion

    // region XOR
    public static byte[] xor(byte[] first_bytes, byte[] second_bytes, int size) {
        byte[] result_bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            result_bytes[i] = (byte) (first_bytes[i] ^ second_bytes[i]);
        }
        return result_bytes;
    }
    // endregion

    // region rotation
    @SuppressWarnings("Duplicates")
    public static void rotate_left(byte[] key_56_bit_bytes) {
        int val0 = key_56_bit_bytes[0] & 0xFF;
        int val1 = key_56_bit_bytes[1] & 0xFF;
        int val2 = key_56_bit_bytes[2] & 0xFF;
        int val3 = key_56_bit_bytes[3] & 0xFF;
        int val4 = key_56_bit_bytes[4] & 0xFF;
        int val5 = key_56_bit_bytes[5] & 0xFF;
        int val6 = key_56_bit_bytes[6] & 0xFF;

        int carry_left = (val0 & 0x80) >> 3;
        val0 = (val0 << 1) | ((val1 & 0x80) >> 7);
        val1 = (val1 << 1) | ((val2 & 0x80) >> 7);
        val2 = (val2 << 1) | ((val3 & 0x80) >> 7);

        // special handling for byte 3
        int carry_right = (val3 & 0x08) >> 3;
        val3 = (((val3 << 1) | ((val4 & 0x80) >> 7)) & ~0x10) | carry_left;

        val4 = (val4 << 1) | ((val5 & 0x80) >> 7);
        val5 = (val5 << 1) | ((val6 & 0x80) >> 7);
        val6 = (val6 << 1) | carry_right;

        key_56_bit_bytes[0] = (byte) val0;
        key_56_bit_bytes[1] = (byte) val1;
        key_56_bit_bytes[2] = (byte) val2;
        key_56_bit_bytes[3] = (byte) val3;
        key_56_bit_bytes[4] = (byte) val4;
        key_56_bit_bytes[5] = (byte) val5;
        key_56_bit_bytes[6] = (byte) val6;
    }

    @SuppressWarnings("Duplicates")
    public static void rotate_left_twice(byte[] key_56_bit_bytes) {
        int val0 = key_56_bit_bytes[0] & 0xFF;
        int val1 = key_56_bit_bytes[1] & 0xFF;
        int val2 = key_56_bit_bytes[2] & 0xFF;
        int val3 = key_56_bit_bytes[3] & 0xFF;
        int val4 = key_56_bit_bytes[4] & 0xFF;
        int val5 = key_56_bit_bytes[5] & 0xFF;
        int val6 = key_56_bit_bytes[6] & 0xFF;

        int carry_left = (val0 & 0xC0) >> 2;
        val0 = (val0 << 2) | ((val1 & 0xC0) >> 6);
        val1 = (val1 << 2) | ((val2 & 0xC0) >> 6);
        val2 = (val2 << 2) | ((val3 & 0xC0) >> 6);

        // special handling for byte 3
        int carry_right = (val3 & 0x0C) >> 2;
        val3 = (((val3 << 2) | ((val4 & 0xC0) >> 6)) & ~0x30) | carry_left;

        val4 = (val4 << 2) | ((val5 & 0xC0) >> 6);
        val5 = (val5 << 2) | ((val6 & 0xC0) >> 6);
        val6 = (val6 << 2) | carry_right;

        key_56_bit_bytes[0] = (byte) val0;
        key_56_bit_bytes[1] = (byte) val1;
        key_56_bit_bytes[2] = (byte) val2;
        key_56_bit_bytes[3] = (byte) val3;
        key_56_bit_bytes[4] = (byte) val4;
        key_56_bit_bytes[5] = (byte) val5;
        key_56_bit_bytes[6] = (byte) val6;
    }

    @SuppressWarnings("Duplicates")
    public static void rotate_right(byte[] key_56_bit_bytes) {
        int val0 = key_56_bit_bytes[0] & 0xFF;
        int val1 = key_56_bit_bytes[1] & 0xFF;
        int val2 = key_56_bit_bytes[2] & 0xFF;
        int val3 = key_56_bit_bytes[3] & 0xFF;
        int val4 = key_56_bit_bytes[4] & 0xFF;
        int val5 = key_56_bit_bytes[5] & 0xFF;
        int val6 = key_56_bit_bytes[6] & 0xFF;

        int carry_left;
        int carry_right;

        carry_right = (val6 & 0x01) << 3;
        val6 = (val6 >> 1) | ((val5 & 0x01) << 7);
        val5 = (val5 >> 1) | ((val4 & 0x01) << 7);
        val4 = (val4 >> 1) | ((val3 & 0x01) << 7);

        carry_left = (val3 & 0x10) << 3;
        val3 = (((val3 >> 1) | ((val2 & 0x01) << 7)) & ~0x08) | carry_right;
        val2 = (val2 >> 1) | ((val1 & 0x01) << 7);
        val1 = (val1 >> 1) | ((val0 & 0x01) << 7);
        val0 = (val0 >> 1) | carry_left;

        key_56_bit_bytes[0] = (byte) val0;
        key_56_bit_bytes[1] = (byte) val1;
        key_56_bit_bytes[2] = (byte) val2;
        key_56_bit_bytes[3] = (byte) val3;
        key_56_bit_bytes[4] = (byte) val4;
        key_56_bit_bytes[5] = (byte) val5;
        key_56_bit_bytes[6] = (byte) val6;
    }

    @SuppressWarnings("Duplicates")
    public static void rotate_right_twice(byte[] key_56_bit_bytes) {
        int val0 = key_56_bit_bytes[0] & 0xFF;
        int val1 = key_56_bit_bytes[1] & 0xFF;
        int val2 = key_56_bit_bytes[2] & 0xFF;
        int val3 = key_56_bit_bytes[3] & 0xFF;
        int val4 = key_56_bit_bytes[4] & 0xFF;
        int val5 = key_56_bit_bytes[5] & 0xFF;
        int val6 = key_56_bit_bytes[6] & 0xFF;

        int carry_left;
        int carry_right;

        carry_right = (val6 & 0x03) << 2;
        val6 = (val6 >> 2) | ((val5 & 0x03) << 6);
        val5 = (val5 >> 2) | ((val4 & 0x03) << 6);
        val4 = (val4 >> 2) | ((val3 & 0x03) << 6);

        carry_left = (val3 & 0x30) << 2;
        val3 = (((val3 >> 2) | ((val2 & 0x03) << 6)) & ~0x0C) | carry_right;
        val2 = (val2 >> 2) | ((val1 & 0x03) << 6);
        val1 = (val1 >> 2) | ((val0 & 0x03) << 6);
        val0 = (val0 >> 2) | carry_left;

        key_56_bit_bytes[0] = (byte) val0;
        key_56_bit_bytes[1] = (byte) val1;
        key_56_bit_bytes[2] = (byte) val2;
        key_56_bit_bytes[3] = (byte) val3;
        key_56_bit_bytes[4] = (byte) val4;
        key_56_bit_bytes[5] = (byte) val5;
        key_56_bit_bytes[6] = (byte) val6;
    }
    // endregion

    // region substitution
    public static byte[] get_substitution(byte[] bytes) {
        int[] substitution_blocks = new int[4];
        substitution_blocks[0] = DESConst.sbox[0][(bytes[0] & 0xFC) >> 2] << 4;
        substitution_blocks[0] |= DESConst.sbox[1][(bytes[0] & 0x03) << 4 | (bytes[1] & 0xF0) >> 4];
        substitution_blocks[1] = DESConst.sbox[2][(bytes[1] & 0x0F) << 2 | (bytes[2] & 0xC0) >> 6] << 4;
        substitution_blocks[1] |= DESConst.sbox[3][(bytes[2] & 0x3F)];
        substitution_blocks[2] = DESConst.sbox[4][(bytes[3] & 0xFC) >> 2] << 4;
        substitution_blocks[2] |= DESConst.sbox[5][(bytes[3] & 0x03) << 4 | (bytes[4] & 0xF0) >> 4];
        substitution_blocks[3] = DESConst.sbox[6][(bytes[4] & 0x0F) << 2 | (bytes[5] & 0xC0) >> 6] << 4;
        substitution_blocks[3] |= DESConst.sbox[7][(bytes[5] & 0x3F)];

        byte[] substitution_bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            substitution_bytes[i] = (byte) substitution_blocks[i];
        }
        return substitution_bytes;
    }
    // endregion

    // region aes algorithm
    public static byte[] des_block_operate(byte[] plain_text_64_bit_bytes, byte[] key_64_bit_bytes, OperationType type) {
        // Initial permutation
        byte[] ip_64_bit_bytes = DESUtils.permute(plain_text_64_bit_bytes, DESConst.ip_table);

        // Key schedule computation: PC-1
        byte[] key_56_bit_bytes = DESUtils.permute(key_64_bit_bytes, DESConst.pc1_table);

        // copy key and input (带有current前缀，表示会不断变化)
        byte[] current_56_bit_key_bytes = Arrays.copyOf(key_56_bit_bytes, key_56_bit_bytes.length);
        byte[] current_64_bit_bytes = Arrays.copyOf(ip_64_bit_bytes, ip_64_bit_bytes.length);

        // 16 rounds
        for (int i = 1; i <= 16; i++) {

            // Key schedule computation: rotate left
            if (type == OperationType.ENCRYPT) {
                if (i == 1 || i == 2 || i == 9 || i == 16) {
                    DESUtils.rotate_left(current_56_bit_key_bytes);
                } else {
                    DESUtils.rotate_left_twice(current_56_bit_key_bytes);
                }
            }
            // Key schedule computation: PC-2
            byte[] current_48_bit_sub_key_bytes = DESUtils.permute(current_56_bit_key_bytes, DESConst.pc2_table);
            // Key schedule computation: rotate right
            if (type == OperationType.DECRYPT) {
                if (i == 16 || i == 15 || i == 8 || i == 1) {
                    DESUtils.rotate_right(current_56_bit_key_bytes);
                } else {
                    DESUtils.rotate_right_twice(current_56_bit_key_bytes);
                }
            }

            // left 32-bit and right 32-bit
            byte[] left_32_bit_bytes = Arrays.copyOfRange(current_64_bit_bytes, 0, 4);
            byte[] right_32_bit_bytes = Arrays.copyOfRange(current_64_bit_bytes, 4, 8);

            // feistel function
            byte[] expansion_48_bit_bytes = DESUtils.permute(right_32_bit_bytes, DESConst.expansion_table);
            byte[] xor_48_bit_bytes = ByteUtils.xor(expansion_48_bit_bytes, current_48_bit_sub_key_bytes, 6);
            byte[] substitution_32_bit_bytes = DESUtils.get_substitution(xor_48_bit_bytes);
            byte[] permutation_32_bit_bytes = DESUtils.permute(substitution_32_bit_bytes, DESConst.p_table);

            // new left 32-bit and new right 32-bit
            byte[] new_left_32_bit_bytes = Arrays.copyOf(right_32_bit_bytes, 4);
            byte[] new_right_32_bit_bytes = ByteUtils.xor(permutation_32_bit_bytes, left_32_bit_bytes, 4);

            // concatenate new-left and new-right
            current_64_bit_bytes = ByteUtils.concatenate(new_left_32_bit_bytes, new_right_32_bit_bytes);
        }

        // Swap one last time
        byte[] swap_bytes = new byte[8];
        System.arraycopy(current_64_bit_bytes, 4, swap_bytes, 0, 4);
        System.arraycopy(current_64_bit_bytes, 0, swap_bytes, 4, 4);

        // Final permutation (undo initial permutation)
        byte[] fp_64_bit_bytes = DESUtils.permute(swap_bytes, DESConst.fp_table);

        return fp_64_bit_bytes;
    }

    public static byte[] des_block_encrypt(byte[] input_64_bit_block, byte[] key_64_bit_bytes) {
        return des_block_operate(input_64_bit_block, key_64_bit_bytes, OperationType.ENCRYPT);
    }

    public static byte[] des_block_decrypt(byte[] input_64_bit_block, byte[] key_64_bit_bytes) {
        return des_block_operate(input_64_bit_block, key_64_bit_bytes, OperationType.DECRYPT);
    }

    @SuppressWarnings("Duplicates")
    public static byte[] des_operate(byte[] input, byte[] key_64_bit_bytes, OperationType type) {
        int block_size = DESConst.DES_BLOCK_SIZE;

        int input_length = input.length;
        if (input_length % block_size != 0) {
            throw new IllegalArgumentException("input's length is not valid");
        }

        byte[] output = new byte[input_length];
        byte[] input_block = new byte[block_size];
        int times = input_length / block_size;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);
            byte[] encrypted_bytes = des_block_operate(input_block, key_64_bit_bytes, type);
            System.arraycopy(encrypted_bytes, 0, output, i * block_size, block_size);
        }
        return output;
    }


    // endregion

}
