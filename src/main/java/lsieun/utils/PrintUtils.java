package lsieun.utils;

import java.util.List;

public class PrintUtils {
    public static void display_hex(List<byte[]> list) {
        int size = list.size();
        for (int i = 0; i < size; i++) {
            byte[] bytes = list.get(i);
            String line = String.format("%02d: %s", i, HexUtils.toHex(bytes));
            System.out.println(line);
        }
    }

    public static void display_hex_2(List<byte[]> list) {
        int size = list.size();
        int half = size / 2;
        for (int i = 0; i < half; i++) {
            byte[] bytes1 = list.get(i);
            byte[] bytes2 = list.get(i + half);
            String line = String.format("%03d: %s, %03d: %s", i, HexUtils.toHex(bytes1), i+half, HexUtils.toHex(bytes2));
            System.out.println(line);
        }
    }
}
