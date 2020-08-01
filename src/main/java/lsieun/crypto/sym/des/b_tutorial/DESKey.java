package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.ArrayList;
import java.util.List;

public class DESKey {
    public static byte[] from_64_to_56_bit_key_bytes(byte[] key_64_bit_bytes) {
        return DESUtils.permute(key_64_bit_bytes, DESConst.pc1_table);
    }

    public static byte[] from_56_to_48_bit_key_bytes(byte[] key_56_bit_bytes) {
        return DESUtils.permute(key_56_bit_bytes, DESConst.pc2_table);
    }

    public static List<byte[]> roll_56_bit_key_bytes(byte[] key_56_bit_bytes, OperationType rd) {
        byte[] tmp_56_bit_bytes = new byte[7];
        System.arraycopy(key_56_bit_bytes, 0, tmp_56_bit_bytes, 0, 7);

        List<byte[]> list = new ArrayList<>();
        for (int i = 1; i <= 16; i++) {
            byte[] current_key;
            if (rd == OperationType.ENCRYPT) {
                if (i == 1 || i == 2 || i == 9 || i == 16) {
                    current_key = rotate_left(tmp_56_bit_bytes);
                } else {
                    current_key = rotate_left_twice(tmp_56_bit_bytes);
                }
            } else {
                if (i == 16 || i == 15 || i == 8 || i == 1) {
                    current_key = rotate_right(tmp_56_bit_bytes);
                } else {
                    current_key = rotate_right_twice(tmp_56_bit_bytes);
                }
            }
            list.add(current_key);

            System.arraycopy(current_key, 0, tmp_56_bit_bytes, 0, 7);
        }

        return list;
    }

    public static List<byte[]> from_56_to_48_bit_sub_key_list(List<byte[]> list) {
        List<byte[]> result_list = new ArrayList<>();
        for (byte[] key_56_bit_bytes : list) {
            byte[] key_48_bit_bytes = DESUtils.permute(key_56_bit_bytes, DESConst.pc2_table);
            result_list.add(key_48_bit_bytes);
        }
        return result_list;
    }

    public static List<byte[]> get_sub_keys(byte[] key_64_bit_bytes) {
        // 64 bit --> 56 bit
        byte[] key_56_bit_bytes = DESKey.from_64_to_56_bit_key_bytes(key_64_bit_bytes);

        // 56 bit --> 56 bit list
        List<byte[]> sub_key_56_bit_list = DESKey.roll_56_bit_key_bytes(key_56_bit_bytes, OperationType.ENCRYPT);

        // 56 bit list --> 48 bit list
        List<byte[]> sub_key_48_bit_list = DESKey.from_56_to_48_bit_sub_key_list(sub_key_56_bit_list);

        return sub_key_48_bit_list;
    }

    public static byte[] rotate_left(byte[] key_56_bit_bytes) {
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

        byte[] result = new byte[7];
        result[0] = (byte) val0;
        result[1] = (byte) val1;
        result[2] = (byte) val2;
        result[3] = (byte) val3;
        result[4] = (byte) val4;
        result[5] = (byte) val5;
        result[6] = (byte) val6;
        return result;
    }

    public static byte[] rotate_left_twice(byte[] bytes) {
        byte[] tmp = rotate_left(bytes);
        return rotate_left(tmp);
    }

    public static byte[] rotate_right(byte[] key_56_bit_bytes) {
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

        byte[] result = new byte[7];
        result[0] = (byte) val0;
        result[1] = (byte) val1;
        result[2] = (byte) val2;
        result[3] = (byte) val3;
        result[4] = (byte) val4;
        result[5] = (byte) val5;
        result[6] = (byte) val6;
        return result;
    }

    public static byte[] rotate_right_twice(byte[] bytes) {
        byte[] tmp = rotate_right(bytes);
        return rotate_right(tmp);
    }

    public static void display_key_schedule(List<byte[]> list) {
        int size = list.size();
        for (int i = 0; i < size; i++) {
            byte[] bytes = list.get(i);
            String line = String.format("%02d: %s", (i + 1), ByteUtils.toBinary(bytes));
            System.out.println(line);
        }
    }
}
