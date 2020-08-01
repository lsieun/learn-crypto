package lsieun.crypto.sym.des.a_basic;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.Arrays;
import java.util.Random;

/**
 * 这是我刚接触Permutation算法时，自己写的几种测试方法，
 * 目的就是验证一下“使用不同的方法，得到的结果是一样的”。
 */
public class Permutation_Different_Method {
    public static void main(String[] args) {
        byte[] bytes = new byte[]{'a', 'b', 'c', 'd', 'A', 'B', 'C', 'D'};

        Random rand = new Random();
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) rand.nextInt();
        }

        byte[] result1 = permute(bytes); // 第一个，这是我自己写的算法
        byte[] result2 = terse_initial_permutation(bytes); // 第二个，这是书上提及的算法
        byte[] result3 = permute3(bytes); // 第三个，这是自己实现的算法
        byte[] result4 = DESUtils.permute(bytes, DESConst.ip_table); // 这是Ultimate算法


        System.out.println(ByteUtils.toBinary(bytes));
        System.out.println(ByteUtils.toBinary(result1));
        System.out.println(ByteUtils.toBinary(result2));
        System.out.println(ByteUtils.toBinary(result3));
        System.out.println(ByteUtils.toBinary(result4));

        System.out.println(Arrays.equals(result1, result2));
        System.out.println(Arrays.equals(result2, result3));
        System.out.println(Arrays.equals(result3, result4));
    }

    public static byte[] permute(byte[] input) {
        byte[] result_bytes = new byte[8];
        result_bytes[0] = getByte(input, 2, false);
        result_bytes[1] = getByte(input, 4, false);
        result_bytes[2] = getByte(input, 6, false);
        result_bytes[3] = getByte(input, 8, false);
        result_bytes[4] = getByte(input, 1, false);
        result_bytes[5] = getByte(input, 3, false);
        result_bytes[6] = getByte(input, 5, false);
        result_bytes[7] = getByte(input, 7, false);
        return result_bytes;
    }

    public static byte getByte(byte[] input, int index, boolean forward) {
        int result = 0;

        int start;
        int step;
        if (forward) {
            start = 0;
            step = 1;
        } else {
            start = 7;
            step = -1;
        }

        for (int i = 0; i < 8; i++) {
            byte b = input[start];
            int shift = 8 - index;
            result = (result << 1) | ((b & 0xFF) >> shift & 0x01);
            start += step;
        }

        return (byte) result;
    }

    public static byte[] terse_initial_permutation(byte[] input) {
        byte[] result = new byte[8];

        int index = 0;
        for (int i = 1; i != 8; i = (i + 2) % 9) {
            int shift = 7 - i;
            for (int j = 7; j >= 0; j--) {
                int old_value = result[index] & 0xFF;
                int input_value = input[j] & 0xFF;
                int bit_value = (input_value >> shift) & 0x01;
                int new_value = (old_value << 1) | bit_value;
                result[index] = (byte) (new_value);
            }
            index++;
        }
        return result;
    }

    public static byte[] permute3(byte[] input) {
        byte[] result_bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            int val = 0;
            for (int j = 0; j < 8; j++) {
                int pos = DESConst.ip_table[i * 8 + j] - 1;

                int t_i = pos / 8;
                int t_j = pos % 8;
                int t_v = input[t_i] & 0xFF;
                int shift = 7 - t_j;
                int t_b = t_v >> shift & 0x01;

                val |= t_b << (7 - j);
            }
            result_bytes[i] = (byte) val;
        }
        return result_bytes;
    }








}
