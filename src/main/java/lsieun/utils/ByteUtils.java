package lsieun.utils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;

public class ByteUtils {
    public static void setAll(byte[] bytes, int val) {
        int length = bytes.length;
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) val;
        }
    }

    public static byte[] add_one(byte[] bytes) {
        return add_one(bytes, bytes.length);
    }

    public static byte[] add_one(byte[] bytes, int counter) {
        byte[] result = Arrays.copyOf(bytes, bytes.length);
        int length = result.length;
        for (int i = 0; i < counter; i++) {
            int index = length - 1 - i;
            int val = (result[index] & 0xFF);
            result[index] = (byte) (val + 1);
            if (val != 0xFF) {
                break;
            }
        }
        return result;
    }

    public static int toInt(byte[] bytes) {
        int length = bytes.length;

        int sum = 0;
        for (int i = 0; i < length; i++) {
            int index = length - 1 - i;
            int val = bytes[index] & 0xFF;
            sum += (val << (i * 8));
        }
        return sum;
    }

    public static boolean is_loop(List<byte[]> list) {
        int size = list.size();
        if (size % 2 != 0) return false;
        int half = size / 2;
        for (int i = 0; i < half; i++) {
            byte[] bytes1 = list.get(i);
            byte[] bytes2 = list.get(i + half);
            if (!Arrays.equals(bytes1, bytes2)) {
                return false;
            }
        }
        return true;
    }

    public static byte[] xor(byte[] bytes1, byte[] bytes2, int num) {
        byte[] result_bytes = new byte[num];
        for (int i = 0; i < num; i++) {
            result_bytes[i] = (byte) (bytes1[i] ^ bytes2[i]);
        }
        return result_bytes;
    }

    public static String toBinary(byte[] bytes) {
        if (bytes == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            toBinary(sb, b);
            sb.append(" ");
        }
        return sb.toString();
    }

    public static String toBinary(byte b) {
        StringBuilder sb = new StringBuilder();
        toBinary(sb, b);
        return sb.toString();
    }

    private static void toBinary(StringBuilder sb, byte b) {
        for (int i = 7; i >= 0; i--) {
            int val = (b >> i) & 0x01;
            sb.append("" + val);
        }
    }

    public static byte[] toBytes(int value) {
        return toBytes(value, Integer.BYTES);
    }

    public static byte[] toBytes(int value, int len) {
        if (len < 1 || len > 4) {
            throw new RuntimeException("len should be 1 <= len <=4");
        }

        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            bytes[len - 1 - i] = (byte) (value >> (8 * i) & 0xFF);
        }
        return bytes;
    }

    public static byte[] toBytes(long value) {
        int size = Long.BYTES;
        byte[] bytes = new byte[size];

        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) ((value >> ((size - 1 - i) * 8)) & 0xFF);
        }

        return bytes;
    }

    public static List<byte[]> toList(byte[] bytes, int block_size) {
        int length = bytes.length;
        int count = length / block_size;

        List<byte[]> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte[] block_bytes = new byte[block_size];
            System.arraycopy(bytes, i * block_size, block_bytes, 0, block_size);
            list.add(block_bytes);
        }
        return list;
    }

    public static byte[] concatenate(byte[] bytes1, byte[] bytes2) {
        int len1 = bytes1.length;
        int len2 = bytes2.length;

        byte[] result_bytes = new byte[len1 + len2];

        System.arraycopy(bytes1, 0, result_bytes, 0, len1);
        System.arraycopy(bytes2, 0, result_bytes, len1, len2);

        return result_bytes;
    }

    public static byte[] concatenate(byte[] bytes1, byte[] bytes2, byte[] bytes3) {
        int len1 = bytes1.length;
        int len2 = bytes2.length;
        int len3 = bytes3.length;

        byte[] result_bytes = new byte[len1 + len2 + len3];

        System.arraycopy(bytes1, 0, result_bytes, 0, len1);
        System.arraycopy(bytes2, 0, result_bytes, len1, len2);
        System.arraycopy(bytes3, 0, result_bytes, len1 + len2, len3);

        return result_bytes;
    }
}
