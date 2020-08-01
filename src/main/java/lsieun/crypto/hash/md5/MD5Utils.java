package lsieun.crypto.hash.md5;

import java.util.Arrays;

public class MD5Utils {
    private static int rotate_left(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    public static int F(int x, int y, int z) {
        return (x & y) | (~x & z);
    }

    public static int G(int x, int y, int z) {
        return (x & z) | (y & ~z);
    }

    public static int H(int x, int y, int z) {
        return (x ^ y ^ z);
    }

    public static int I(int x, int y, int z) {
        return y ^ (x | ~z);
    }

    public static int round(TriFunction<Integer, Integer, Integer, Integer> f,
                            int a, int b, int c, int d,
                            int x, int s, int ac) {

        int result1 = f.apply(b, c, d);
        int result2 = result1 + a + x + ac;
        int result3 = rotate_left(result2, s);
        int result4 = result3 + b;
        return result4;
    }

    public static void md5_block_operate(byte[] input, int[] hash) {
        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];

        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            // NOTE: 这里是容易出错的地方，如果省略了"& 0xFF"操作，计算结果就会不正确
            x[i] =  (input[(i * 4 + 3)] & 0xFF) << 24 |
                    (input[(i * 4 + 2)] & 0xFF) << 16 |
                    (input[(i * 4 + 1)] & 0xFF) << 8 |
                    (input[(i * 4 + 0)] & 0xFF);
        }

        /* Round 1 */
        a = round(MD5Utils::F, a, b, c, d, x[0], 7, 0xd76aa478); /* 1 */
        d = round(MD5Utils::F, d, a, b, c, x[1], 12, 0xe8c7b756); /* 2 */
        c = round(MD5Utils::F, c, d, a, b, x[2], 17, 0x242070db); /* 3 */
        b = round(MD5Utils::F, b, c, d, a, x[3], 22, 0xc1bdceee); /* 4 */
        a = round(MD5Utils::F, a, b, c, d, x[4], 7, 0xf57c0faf); /* 5 */
        d = round(MD5Utils::F, d, a, b, c, x[5], 12, 0x4787c62a); /* 6 */
        c = round(MD5Utils::F, c, d, a, b, x[6], 17, 0xa8304613); /* 7 */
        b = round(MD5Utils::F, b, c, d, a, x[7], 22, 0xfd469501); /* 8 */
        a = round(MD5Utils::F, a, b, c, d, x[8], 7, 0x698098d8); /* 9 */
        d = round(MD5Utils::F, d, a, b, c, x[9], 12, 0x8b44f7af); /* 10 */
        c = round(MD5Utils::F, c, d, a, b, x[10], 17, 0xFFff5bb1); /* 11 */
        b = round(MD5Utils::F, b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
        a = round(MD5Utils::F, a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
        d = round(MD5Utils::F, d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
        c = round(MD5Utils::F, c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
        b = round(MD5Utils::F, b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

        /* Round 2 */
        a = round(MD5Utils::G, a, b, c, d, x[1], 5, 0xf61e2562); /* 17 */
        d = round(MD5Utils::G, d, a, b, c, x[6], 9, 0xc040b340); /* 18 */
        c = round(MD5Utils::G, c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
        b = round(MD5Utils::G, b, c, d, a, x[0], 20, 0xe9b6c7aa); /* 20 */
        a = round(MD5Utils::G, a, b, c, d, x[5], 5, 0xd62f105d); /* 21 */
        d = round(MD5Utils::G, d, a, b, c, x[10], 9, 0x2441453); /* 22 */
        c = round(MD5Utils::G, c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
        b = round(MD5Utils::G, b, c, d, a, x[4], 20, 0xe7d3fbc8); /* 24 */
        a = round(MD5Utils::G, a, b, c, d, x[9], 5, 0x21e1cde6); /* 25 */
        d = round(MD5Utils::G, d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
        c = round(MD5Utils::G, c, d, a, b, x[3], 14, 0xf4d50d87); /* 27 */
        b = round(MD5Utils::G, b, c, d, a, x[8], 20, 0x455a14ed); /* 28 */
        a = round(MD5Utils::G, a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
        d = round(MD5Utils::G, d, a, b, c, x[2], 9, 0xfcefa3f8); /* 30 */
        c = round(MD5Utils::G, c, d, a, b, x[7], 14, 0x676f02d9); /* 31 */
        b = round(MD5Utils::G, b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        a = round(MD5Utils::H, a, b, c, d, x[5], 4, 0xFFfa3942); /* 33 */
        d = round(MD5Utils::H, d, a, b, c, x[8], 11, 0x8771f681); /* 34 */
        c = round(MD5Utils::H, c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
        b = round(MD5Utils::H, b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
        a = round(MD5Utils::H, a, b, c, d, x[1], 4, 0xa4beea44); /* 37 */
        d = round(MD5Utils::H, d, a, b, c, x[4], 11, 0x4bdecfa9); /* 38 */
        c = round(MD5Utils::H, c, d, a, b, x[7], 16, 0xf6bb4b60); /* 39 */
        b = round(MD5Utils::H, b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
        a = round(MD5Utils::H, a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
        d = round(MD5Utils::H, d, a, b, c, x[0], 11, 0xeaa127fa); /* 42 */
        c = round(MD5Utils::H, c, d, a, b, x[3], 16, 0xd4ef3085); /* 43 */
        b = round(MD5Utils::H, b, c, d, a, x[6], 23, 0x4881d05); /* 44 */
        a = round(MD5Utils::H, a, b, c, d, x[9], 4, 0xd9d4d039); /* 45 */
        d = round(MD5Utils::H, d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
        c = round(MD5Utils::H, c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
        b = round(MD5Utils::H, b, c, d, a, x[2], 23, 0xc4ac5665); /* 48 */

        /* Round 4 */
        a = round(MD5Utils::I, a, b, c, d, x[0], 6, 0xf4292244); /* 49 */
        d = round(MD5Utils::I, d, a, b, c, x[7], 10, 0x432aff97); /* 50 */
        c = round(MD5Utils::I, c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
        b = round(MD5Utils::I, b, c, d, a, x[5], 21, 0xfc93a039); /* 52 */
        a = round(MD5Utils::I, a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
        d = round(MD5Utils::I, d, a, b, c, x[3], 10, 0x8f0ccc92); /* 54 */
        c = round(MD5Utils::I, c, d, a, b, x[10], 15, 0xFFeff47d); /* 55 */
        b = round(MD5Utils::I, b, c, d, a, x[1], 21, 0x85845dd1); /* 56 */
        a = round(MD5Utils::I, a, b, c, d, x[8], 6, 0x6fa87e4f); /* 57 */
        d = round(MD5Utils::I, d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
        c = round(MD5Utils::I, c, d, a, b, x[6], 15, 0xa3014314); /* 59 */
        b = round(MD5Utils::I, b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
        a = round(MD5Utils::I, a, b, c, d, x[4], 6, 0xf7537e82); /* 61 */
        d = round(MD5Utils::I, d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
        c = round(MD5Utils::I, c, d, a, b, x[2], 15, 0x2ad7d2bb); /* 63 */
        b = round(MD5Utils::I, b, c, d, a, x[9], 21, 0xeb86d391); /* 64 */

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
    }

    public static byte[] md5_hash(byte[] input) {
        byte[] input_block = new byte[MD5Const.MD5_BLOCK_SIZE];
        int len = input.length;
        int quotient = len / MD5Const.MD5_BLOCK_SIZE;
        int remainder = len % MD5Const.MD5_BLOCK_SIZE;
        
        // XXX should verify that len < 2^64, but since len is only 32 bits, this won’t
        // be a problem.
        int[] hash = Arrays.copyOf(MD5Const.MD5_INITIAL_HASH, MD5Const.MD5_RESULT_SIZE);

        for (int i = 0; i < quotient; i++) {
            System.arraycopy(input, i * MD5Const.MD5_BLOCK_SIZE, input_block, 0, MD5Const.MD5_BLOCK_SIZE);
            md5_block_operate(input_block, hash);
        }

        int length_in_bits = len * 8;
        if (remainder >= MD5Const.MD5_PADDING_THRESHOLD) {
            // Special handling for blocks between 56 and 64 bytes
            // (not enough room for the 8 bytes of length, but also
            // not enough to fill up a block)
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * MD5Const.MD5_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            md5_block_operate(input_block, hash);

            Arrays.fill(input_block, (byte) 0);
            fill_length_in_bits(input_block, length_in_bits);
            md5_block_operate(input_block, hash);
        } else {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * MD5Const.MD5_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            fill_length_in_bits(input_block, length_in_bits);
            md5_block_operate(input_block, hash);
        }

        return encode(hash);
    }

    public static void fill_length_in_bits(byte[] input_block, int length_in_bits) {
        input_block[MD5Const.MD5_BLOCK_SIZE - 5] = (byte) ((length_in_bits & 0xFF000000) >> 24);
        input_block[MD5Const.MD5_BLOCK_SIZE - 6] = (byte) ((length_in_bits & 0x00FF0000) >> 16);
        input_block[MD5Const.MD5_BLOCK_SIZE - 7] = (byte) ((length_in_bits & 0x0000FF00) >> 8);
        input_block[MD5Const.MD5_BLOCK_SIZE - 8] = (byte) (length_in_bits & 0x000000FF);
    }

    public static byte[] encode(int[] hash) {
        byte[] bytes = new byte[MD5Const.MD5_OUTPUT_SIZE];

        bytes[0] = (byte) (hash[0] & 0xFF);
        bytes[1] = (byte) ((hash[0] >>> 8) & 0xFF);
        bytes[2] = (byte) ((hash[0] >>> 16) & 0xFF);
        bytes[3] = (byte) ((hash[0] >>> 24) & 0xFF);

        bytes[4] = (byte) (hash[1] & 0xFF);
        bytes[5] = (byte) ((hash[1] >>> 8) & 0xFF);
        bytes[6] = (byte) ((hash[1] >>> 16) & 0xFF);
        bytes[7] = (byte) ((hash[1] >>> 24) & 0xFF);

        bytes[8] = (byte) (hash[2] & 0xFF);
        bytes[9] = (byte) ((hash[2] >>> 8) & 0xFF);
        bytes[10] = (byte) ((hash[2] >>> 16) & 0xFF);
        bytes[11] = (byte) ((hash[2] >>> 24) & 0xFF);

        bytes[12] = (byte) (hash[3] & 0xFF);
        bytes[13] = (byte) ((hash[3] >>> 8) & 0xFF);
        bytes[14] = (byte) ((hash[3] >>> 16) & 0xFF);
        bytes[15] = (byte) ((hash[3] >>> 24) & 0xFF);

        return bytes;
    }
}
