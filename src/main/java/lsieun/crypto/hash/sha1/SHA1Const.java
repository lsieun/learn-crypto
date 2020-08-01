package lsieun.crypto.hash.sha1;

public class SHA1Const {
    public static final int SHA1_PADDING_THRESHOLD = 56;
    public static final int SHA1_BLOCK_SIZE = 64;
    public static final int SHA1_OUTPUT_SIZE = 20;
    public static final int SHA1_RESULT_SIZE = 5;

    public static final int k[] = {
            0x5a827999, // 0 <= t <= 19
            0x6ed9eba1, // 20 <= t <= 39
            0x8f1bbcdc, // 40 <= t <= 59
            0xca62c1d6 // 60 <= t <= 79
    };

    public static int SHA1_INITIAL_HASH[] = {
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
    };

    public static final boolean DEBUG = true;
}
