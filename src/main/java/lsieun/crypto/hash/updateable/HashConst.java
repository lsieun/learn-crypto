package lsieun.crypto.hash.updateable;

public class HashConst {
    public static final int DIGEST_BLOCK_SIZE = 64;
    public static final int PADDING_THRESHOLD = 56;

    public static int INITIAL_HASH[] = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
    };
}
