package lsieun.utils;

import java.util.Arrays;

// TODO: 实现不同的padding
public class PaddingUtils {

    public static byte[] add_nist_8003a_padding(byte[] input, int block_size) {
        // calculate padding length
        int length = input.length;
        int padding_len = block_size - (length % block_size);

        // This implements NIST 800-3A padding
        byte[] output = new byte[length + padding_len];
        System.arraycopy(input, 0, output, 0, length);
        output[length] = (byte) 0x80;
        return output;
    }

    public static byte[] remove_nist_8003a_padding(byte[] input) {
        int length = input.length;
        int index = length - 1;
        for (; index >= 0; index--) {
            byte b = input[index];
            if ((b & 0xFF) == 0x80) {
                break;
            }
        }
        return Arrays.copyOf(input, index);
    }

    public static byte[] add_pkcs5_padding(byte[] input, int block_size) {
        // calculate padding length
        int length = input.length;
        int padding_len = block_size - (length % block_size);
        byte[] output = new byte[length + padding_len];

        // This implements PKCS #5 padding.
        System.arraycopy(input, 0, output, 0, length);
        for (int i = 0; i < padding_len; i++) {
            output[length + i] = (byte) padding_len;
        }
        return output;
    }

    public static byte[] remove_pkcs5_padding(byte[] input) {
        // calculate padding length
        int length = input.length;
        int padded_len = input[length - 1];
        int remain_len = length - padded_len;

        // remove PKCS #5 padding.
        byte[] output = new byte[remain_len];
        System.arraycopy(input, 0, output, 0, remain_len);
        return output;
    }
}
