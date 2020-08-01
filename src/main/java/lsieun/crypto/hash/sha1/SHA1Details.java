package lsieun.crypto.hash.sha1;

import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Formatter;

@SuppressWarnings("Duplicates")
public class SHA1Details {
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

    public static void sha1_block_operate(byte[] block, int[] hash) {
        int[] W = new int[80];
        // First 16 blocks of W are the original 16 blocks of the input
        for (int i = 0; i < 80; i++) {
            if (i < 16) {
                W[i] = ((block[(i * 4)] & 0xFF) << 24) |
                        ((block[(i * 4) + 1] & 0xFF) << 16) |
                        ((block[(i * 4) + 2] & 0xFF) << 8) |
                        (block[(i * 4) + 3] & 0xFF);
            } else {
                W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
                // Rotate left operation
                W[i] = (W[i] << 1) | ((W[i] >>> 31) & 0x01);
            }
        }

        if (SHA1Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("Block Contents:%n");
            for (int i = 0; i < 16; i++) {
                fm.format("    W[%02d] = %s%n", i, HexUtils.toHex(W[i]));
            }
            fm.format("=======================================================================================%n");
            System.out.println(sb.toString());
        }

        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];
        int e = hash[4];

        if (SHA1Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("Current A/B/C/D/E:%n");
            fm.format("    A: %s%n", HexUtils.toHex(a));
            fm.format("    B: %s%n", HexUtils.toHex(b));
            fm.format("    C: %s%n", HexUtils.toHex(c));
            fm.format("    D: %s%n", HexUtils.toHex(d));
            fm.format("    E: %s%n", HexUtils.toHex(e));
            System.out.println(sb.toString());
        }


        if (SHA1Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("          A         B         C         D         E        rotation    W[t]    func_val");
            System.out.println(sb.toString());
        }

        for (int t = 0; t < 80; t++) {
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

            if (SHA1Const.DEBUG) {
                StringBuilder sb = new StringBuilder();
                Formatter fm = new Formatter(sb);
                fm.format("t=%02d: %8s  %8s  %8s  %8s  %8s |   %8s  %8s  %8s",
                        t,
                        HexUtils.toHex(a),
                        HexUtils.toHex(b),
                        HexUtils.toHex(c),
                        HexUtils.toHex(d),
                        HexUtils.toHex(e),
                        HexUtils.toHex(rotation),
                        HexUtils.toHex(w),
                        HexUtils.toHex(function_value)
                );
                System.out.println(sb.toString());
            }
        }

        if (SHA1Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("%n");
            fm.format("Current hash value:%n");
            fm.format("    H[0]: %s + %s = %s%n", HexUtils.toHex(hash[0]), HexUtils.toHex(a), HexUtils.toHex(hash[0] + a));
            fm.format("    H[1]: %s + %s = %s%n", HexUtils.toHex(hash[1]), HexUtils.toHex(b), HexUtils.toHex(hash[1] + b));
            fm.format("    H[2]: %s + %s = %s%n", HexUtils.toHex(hash[2]), HexUtils.toHex(c), HexUtils.toHex(hash[2] + c));
            fm.format("    H[3]: %s + %s = %s%n", HexUtils.toHex(hash[3]), HexUtils.toHex(d), HexUtils.toHex(hash[3] + d));
            fm.format("    H[4]: %s + %s = %s%n", HexUtils.toHex(hash[4]), HexUtils.toHex(e), HexUtils.toHex(hash[4] + e));
            fm.format("=======================================================================================%n");
            System.out.println(sb.toString());
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
    }

    public static byte[] sha1_hash(byte[] input, int len) {
        int[] hash = new int[SHA1Const.SHA1_RESULT_SIZE];
        int length_in_bits = len * 8;

        hash[0] = SHA1Const.SHA1_INITIAL_HASH[0];
        hash[1] = SHA1Const.SHA1_INITIAL_HASH[1];
        hash[2] = SHA1Const.SHA1_INITIAL_HASH[2];
        hash[3] = SHA1Const.SHA1_INITIAL_HASH[3];
        hash[4] = SHA1Const.SHA1_INITIAL_HASH[4];

        if (SHA1Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("Initial hash value:%n");
            for (int i = 0; i < hash.length; i++) {
                fm.format("    H[%d] = %s%n", i, HexUtils.toHex(hash[i]));
            }
            fm.format("=======================================================================================%n");
            System.out.println(sb.toString());
        }

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
        byte[] bytes = new byte[20];

        bytes[0] = (byte) ((hash[0] >>> 24) & 0xff);
        bytes[1] = (byte) ((hash[0] >>> 16) & 0xff);
        bytes[2] = (byte) ((hash[0] >>> 8) & 0xff);
        bytes[3] = (byte) (hash[0] & 0xff);

        bytes[4] = (byte) ((hash[1] >>> 24) & 0xff);
        bytes[5] = (byte) ((hash[1] >>> 16) & 0xff);
        bytes[6] = (byte) ((hash[1] >>> 8) & 0xff);
        bytes[7] = (byte) (hash[1] & 0xff);

        bytes[8] = (byte) ((hash[2] >>> 24) & 0xff);
        bytes[9] = (byte) ((hash[2] >>> 16) & 0xff);
        bytes[10] = (byte) ((hash[2] >>> 8) & 0xff);
        bytes[11] = (byte) (hash[2] & 0xff);

        bytes[12] = (byte) ((hash[3] >>> 24) & 0xff);
        bytes[13] = (byte) ((hash[3] >>> 16) & 0xff);
        bytes[14] = (byte) ((hash[3] >>> 8) & 0xff);
        bytes[15] = (byte) (hash[3] & 0xff);

        bytes[16] = (byte) ((hash[4] >>> 24) & 0xff);
        bytes[17] = (byte) ((hash[4] >>> 16) & 0xff);
        bytes[18] = (byte) ((hash[4] >>> 8) & 0xff);
        bytes[19] = (byte) (hash[4] & 0xff);

        return bytes;
    }
}
