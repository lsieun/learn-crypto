package lsieun.cert.oid;

import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;

public class OIDUtils {
    public static String format(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);

        // val = 40 * a + b
        int val = (bytes[0] & 0xFF);
        int a = val / 40;
        int b = val % 40;
        fm.format("%d.%d", a, b);

        int length = bytes.length;
        int index = 1;
        while (index < length) {
            int span = 0;
            for (int i = index; i < length; i++) {
                span = i - index + 1;

                int c = (bytes[i] & 0xFF);
                if ((c & 0x80) == 0x00) {
                    break;
                }
            }

            int total = 0;
            for (int i = 0; i < span; i++) {
                total = (total << 7) + (bytes[index + i] & 0x7F);
            }
            fm.format(".%d", total);

            index += span;
        }

        return sb.toString();
    }

    public static byte[] parse(String oid_str) {
        List<Byte> list = new ArrayList<>();

        String[] array = oid_str.split("\\.");
        int a = Integer.parseInt(array[0]);
        int b = Integer.parseInt(array[1]);
        byte first_byte = (byte) (a * 40 + b);
        list.add(first_byte);

        int length = array.length;
        for (int i = 2; i < length; i++) {
            int val = Integer.parseInt(array[i]);
            String binary_str = Integer.toString(val, 2);
            int binary_len = binary_str.length();
            int quotient = binary_len / 7;
            int remainder = binary_len % 7;
            if (remainder != 0) {
                quotient++;
            }
            byte[] sub_bytes = new byte[quotient];
            for (int j = 0; j < quotient; j++) {
                int c = val & 0x7F;
                if (j != 0) {
                    c |= 0x80;
                }
                sub_bytes[quotient - 1 - j] = (byte) c;
                val >>>= 7;
            }

            for(byte item : sub_bytes) {
                list.add(item);
            }

        }

        int size = list.size();
        byte[] bytes = new byte[size];
        for (int i=0;i<size;i++) {
            bytes[i] = list.get(i);
        }

        return bytes;
    }

}
