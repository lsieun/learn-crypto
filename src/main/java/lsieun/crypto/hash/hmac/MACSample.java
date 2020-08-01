package lsieun.crypto.hash.hmac;

import java.nio.charset.StandardCharsets;

public class MACSample {
    public static final byte[] key_bytes = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    // HmacMD5: 04b334fc179968bdaa9208b84665f758
    // HmacSHA1: cbe2b57ae48beb9c460523e0296990d7f322909c
    // HmacSHA256: 0791cc4a35c91557aa97edbd0e197719cf2e5fde9af2d86627fac0e40108e54a
    public static final byte[] data = "abcdefghijklmnopqrstuvxyz".getBytes(StandardCharsets.UTF_8);
}
