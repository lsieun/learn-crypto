package lsieun.crypto.hash.sha1;

import java.util.Arrays;

@SuppressWarnings("Duplicates")
public class SHA1Utils {
    // ch is functions 0 - 19
    public static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    // parity is functions 20 - 39 & 60 - 79
    public static int parity(int x, int y, int z) {
        return x ^ y ^ z;
    }

    // maj is functions 40 - 59
    public static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    public static void sha1_block_operate(byte[] input_block, int[] hash) {
        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            x[i] =  ((input_block[(i * 4) + 0] & 0xFF) << 24) |
                    ((input_block[(i * 4) + 1] & 0xFF) << 16) |
                    ((input_block[(i * 4) + 2] & 0xFF) << 8) |
                    ((input_block[(i * 4) + 3] & 0xFF) << 0);
        }

        int[] W = new int[80];
        // First 16 blocks of W are the original 16 blocks of the input
        for (int i = 0; i < 80; i++) {
            if (i < 16) {
                W[i] = x[i];
            } else {
                W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
                // Rotate left operation
                W[i] = (W[i] << 1) | ((W[i] >>> 31) & 0x01);
            }
        }

        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];
        int e = hash[4];

        for (int t = 0; t < 80; t++) {
            // NOTE: 这里我曾经遇到过个一个问题，之前我使用"a >> 27"，结果总是不对，当我换成"a >>> 27"之后，结果才正确
            // 这个问题，就很好的说明了>> 和 >>> 两者之间的区别
            int rotation = ((a << 5) | (a >>> 27));
            int constant = SHA1Const.k[(t / 20)];
            int w = W[t];

            int function_value;
            if (t <= 19) {
                function_value = ch(b, c, d);
            } else if (t <= 39) {
                function_value = parity(b, c, d);
            } else if (t <= 59) {
                function_value = maj(b, c, d);
            } else {
                function_value = parity(b, c, d);
            }

            int temp = rotation + e + constant + w + function_value;

            e = d;
            d = c;
            c = ((b << 30) | (b >>> 2)); // NOTE: 这里要用>>>，而不能用>>，因为当b为负数时，就会出现错误结果。或者使用c = Integer.rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
    }

    public static byte[] sha1_hash(byte[] input) {
        int len = input.length;
        int[] hash = new int[SHA1Const.SHA1_RESULT_SIZE];
        int length_in_bits = len * 8;

        hash[0] = SHA1Const.SHA1_INITIAL_HASH[0];
        hash[1] = SHA1Const.SHA1_INITIAL_HASH[1];
        hash[2] = SHA1Const.SHA1_INITIAL_HASH[2];
        hash[3] = SHA1Const.SHA1_INITIAL_HASH[3];
        hash[4] = SHA1Const.SHA1_INITIAL_HASH[4];

        int quotient = len / SHA1Const.SHA1_BLOCK_SIZE;
        int remainder = len % SHA1Const.SHA1_BLOCK_SIZE;
        byte[] input_block = new byte[SHA1Const.SHA1_BLOCK_SIZE];
        for (int i = 0; i < quotient; i++) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, i * SHA1Const.SHA1_BLOCK_SIZE, input_block, 0, SHA1Const.SHA1_BLOCK_SIZE);
            sha1_block_operate(input_block, hash);
        }

        if (remainder >= SHA1Const.SHA1_PADDING_THRESHOLD) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * SHA1Const.SHA1_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            sha1_block_operate(input_block, hash);

            Arrays.fill(input_block, (byte) 0);
            fill_length_in_bits(input_block, length_in_bits);
            sha1_block_operate(input_block, hash);
        } else {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * SHA1Const.SHA1_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            fill_length_in_bits(input_block, length_in_bits);
            sha1_block_operate(input_block, hash);
        }

        return encode(hash);
    }

    public static void fill_length_in_bits(byte[] input_block, int length_in_bits) {
        input_block[SHA1Const.SHA1_BLOCK_SIZE - 4] = (byte) ((length_in_bits & 0xFF000000) >> 24);
        input_block[SHA1Const.SHA1_BLOCK_SIZE - 3] = (byte) ((length_in_bits & 0x00FF0000) >> 16);
        input_block[SHA1Const.SHA1_BLOCK_SIZE - 2] = (byte) ((length_in_bits & 0x0000FF00) >> 8);
        input_block[SHA1Const.SHA1_BLOCK_SIZE - 1] = (byte) (length_in_bits & 0x000000FF);
    }

    public static byte[] encode(int[] hash) {
        byte[] bytes = new byte[SHA1Const.SHA1_OUTPUT_SIZE];

        bytes[0] = (byte) ((hash[0] >>> 24) & 0xFF);
        bytes[1] = (byte) ((hash[0] >>> 16) & 0xFF);
        bytes[2] = (byte) ((hash[0] >>> 8) & 0xFF);
        bytes[3] = (byte) (hash[0] & 0xFF);

        bytes[4] = (byte) ((hash[1] >>> 24) & 0xFF);
        bytes[5] = (byte) ((hash[1] >>> 16) & 0xFF);
        bytes[6] = (byte) ((hash[1] >>> 8) & 0xFF);
        bytes[7] = (byte) (hash[1] & 0xFF);

        bytes[8] = (byte) ((hash[2] >>> 24) & 0xFF);
        bytes[9] = (byte) ((hash[2] >>> 16) & 0xFF);
        bytes[10] = (byte) ((hash[2] >>> 8) & 0xFF);
        bytes[11] = (byte) (hash[2] & 0xFF);

        bytes[12] = (byte) ((hash[3] >>> 24) & 0xFF);
        bytes[13] = (byte) ((hash[3] >>> 16) & 0xFF);
        bytes[14] = (byte) ((hash[3] >>> 8) & 0xFF);
        bytes[15] = (byte) (hash[3] & 0xFF);

        bytes[16] = (byte) ((hash[4] >>> 24) & 0xFF);
        bytes[17] = (byte) ((hash[4] >>> 16) & 0xFF);
        bytes[18] = (byte) ((hash[4] >>> 8) & 0xFF);
        bytes[19] = (byte) (hash[4] & 0xFF);

        return bytes;
    }
}
