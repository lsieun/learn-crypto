package lsieun.crypto.hash.sha256;

import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Formatter;

@SuppressWarnings("Duplicates")
public class SHA256Details {
    public static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    public static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    public static int rotr(int x, int n) {
        return (x >>> n) | ((x) << (32 - n));
    }

    public static int shr(int x, int n) {
        return x >>> n;
    }

    public static int sigma_rot(int x, int i) {
        return rotr(x, i != 0 ? 6 : 2) ^ rotr(x, i != 0 ? 11 : 13) ^ rotr(x, i != 0 ? 25 : 22);
    }

    public static int sigma_shr(int x, int i) {
        return rotr(x, i != 0 ? 17 : 7) ^ rotr(x, i != 0 ? 19 : 18) ^ shr(x, i != 0 ? 10 : 3);
    }

    public static void sha256_block_operate(byte[] block, int[] hash) {
        int[] W = new int[64];
        for (int t = 0; t < 64; t++) {
            if (t < 16) {
                W[t] = ((block[(t * 4)] & 0xFF) << 24) |
                        ((block[(t * 4) + 1] & 0xFF) << 16) |
                        ((block[(t * 4) + 2] & 0xFF) << 8) |
                        (block[(t * 4) + 3] & 0xFF);
            } else {
                W[t] = sigma_shr(W[t - 2], 1) +
                        W[t - 7] +
                        sigma_shr(W[t - 15], 0) +
                        W[t - 16];
            }
        }

        if (SHA256Const.DEBUG) {
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
        int f = hash[5];
        int g = hash[6];
        int h = hash[7];

        if (SHA256Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("Current A/B/C/D/E/F/G/H:%n");
            fm.format("    A: %s%n", HexUtils.toHex(a));
            fm.format("    B: %s%n", HexUtils.toHex(b));
            fm.format("    C: %s%n", HexUtils.toHex(c));
            fm.format("    D: %s%n", HexUtils.toHex(d));
            fm.format("    E: %s%n", HexUtils.toHex(e));
            fm.format("    F: %s%n", HexUtils.toHex(f));
            fm.format("    G: %s%n", HexUtils.toHex(g));
            fm.format("    H: %s%n", HexUtils.toHex(h));
            System.out.println(sb.toString());
        }

        if (SHA256Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("          A         B         C         D         E         F         G         H");
            System.out.println(sb.toString());
        }

        for (int t = 0; t < 64; t++) {
            int temp1 = h + sigma_rot(e, 1) + ch(e, f, g) + SHA256Const.k[t] + W[t];
            int temp2 = sigma_rot(a, 0) + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;

            if (SHA256Const.DEBUG) {
                StringBuilder sb = new StringBuilder();
                Formatter fm = new Formatter(sb);
                fm.format("t=%02d: %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s",
                        t,
                        HexUtils.toHex(a),
                        HexUtils.toHex(b),
                        HexUtils.toHex(c),
                        HexUtils.toHex(d),
                        HexUtils.toHex(e),
                        HexUtils.toHex(f),
                        HexUtils.toHex(g),
                        HexUtils.toHex(h)
                );
                System.out.println(sb.toString());
            }
        }

        if (SHA256Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("%n");
            fm.format("Current hash value:%n");
            fm.format("    H[0]: %s + %s = %s%n", HexUtils.toHex(hash[0]), HexUtils.toHex(a), HexUtils.toHex(hash[0] + a));
            fm.format("    H[1]: %s + %s = %s%n", HexUtils.toHex(hash[1]), HexUtils.toHex(b), HexUtils.toHex(hash[1] + b));
            fm.format("    H[2]: %s + %s = %s%n", HexUtils.toHex(hash[2]), HexUtils.toHex(c), HexUtils.toHex(hash[2] + c));
            fm.format("    H[3]: %s + %s = %s%n", HexUtils.toHex(hash[3]), HexUtils.toHex(d), HexUtils.toHex(hash[3] + d));
            fm.format("    H[4]: %s + %s = %s%n", HexUtils.toHex(hash[4]), HexUtils.toHex(e), HexUtils.toHex(hash[4] + e));
            fm.format("    H[5]: %s + %s = %s%n", HexUtils.toHex(hash[5]), HexUtils.toHex(f), HexUtils.toHex(hash[5] + f));
            fm.format("    H[6]: %s + %s = %s%n", HexUtils.toHex(hash[6]), HexUtils.toHex(g), HexUtils.toHex(hash[6] + g));
            fm.format("    H[7]: %s + %s = %s%n", HexUtils.toHex(hash[7]), HexUtils.toHex(h), HexUtils.toHex(hash[7] + h));
            fm.format("=======================================================================================%n");
            System.out.println(sb.toString());
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    public static byte[] sha256_hash(byte[] input, int len) {
        int[] hash = new int[SHA256Const.SHA256_RESULT_SIZE];
        int length_in_bits = len * 8;

        hash[0] = SHA256Const.SHA256_INITIAL_HASH[0];
        hash[1] = SHA256Const.SHA256_INITIAL_HASH[1];
        hash[2] = SHA256Const.SHA256_INITIAL_HASH[2];
        hash[3] = SHA256Const.SHA256_INITIAL_HASH[3];
        hash[4] = SHA256Const.SHA256_INITIAL_HASH[4];
        hash[5] = SHA256Const.SHA256_INITIAL_HASH[5];
        hash[6] = SHA256Const.SHA256_INITIAL_HASH[6];
        hash[7] = SHA256Const.SHA256_INITIAL_HASH[7];

        if (SHA256Const.DEBUG) {
            StringBuilder sb = new StringBuilder();
            Formatter fm = new Formatter(sb);
            fm.format("Initial hash value:%n");
            for (int i = 0; i < hash.length; i++) {
                fm.format("    H[%d] = %s%n", i, HexUtils.toHex(hash[i]));
            }
            fm.format("=======================================================================================%n");
            System.out.println(sb.toString());
        }

        int quotient = len / SHA256Const.SHA256_BLOCK_SIZE;
        int remainder = len % SHA256Const.SHA256_BLOCK_SIZE;
        byte[] input_block = new byte[SHA256Const.SHA256_BLOCK_SIZE];
        for (int i = 0; i < quotient; i++) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, i * SHA256Const.SHA256_BLOCK_SIZE, input_block, 0, SHA256Const.SHA256_BLOCK_SIZE);
            sha256_block_operate(input_block, hash);
        }

        if (remainder >= SHA256Const.SHA256_PADDING_THRESHOLD) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * SHA256Const.SHA256_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            sha256_block_operate(input_block, hash);

            Arrays.fill(input_block, (byte) 0);
            fill_length_in_bits(input_block, length_in_bits);
            sha256_block_operate(input_block, hash);
        } else {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * SHA256Const.SHA256_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            fill_length_in_bits(input_block, length_in_bits);
            sha256_block_operate(input_block, hash);
        }

        return encode(hash);
    }

    public static void fill_length_in_bits(byte[] input_block, int length_in_bits) {
        input_block[SHA256Const.SHA256_BLOCK_SIZE - 4] = (byte) ((length_in_bits & 0xFF000000) >> 24);
        input_block[SHA256Const.SHA256_BLOCK_SIZE - 3] = (byte) ((length_in_bits & 0x00FF0000) >> 16);
        input_block[SHA256Const.SHA256_BLOCK_SIZE - 2] = (byte) ((length_in_bits & 0x0000FF00) >> 8);
        input_block[SHA256Const.SHA256_BLOCK_SIZE - 1] = (byte) (length_in_bits & 0x000000FF);
    }

    public static byte[] encode(int[] hash) {
        int size = hash.length * 4;
        byte[] bytes = new byte[size];

        for (int i = 0; i < size; i += 4) {
            int quotient = i / 4;
            bytes[i + 0] = (byte) ((hash[quotient] >>> 24) & 0xff);
            bytes[i + 1] = (byte) ((hash[quotient] >>> 16) & 0xff);
            bytes[i + 2] = (byte) ((hash[quotient] >>> 8) & 0xff);
            bytes[i + 3] = (byte) (hash[quotient] & 0xff);
        }

        return bytes;
    }
}
