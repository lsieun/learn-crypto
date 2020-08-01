package lsieun.crypto.hash.md5;

import java.nio.charset.StandardCharsets;

public class MD5Example {
    // f29939a25efabaef3b87e2cbfe641315
    public static final byte[] input_52_bytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".getBytes(StandardCharsets.UTF_8);

    // 27eca74a76daae63f472b250b5bcff9d
    public static final byte[] input_56_bytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123".getBytes(StandardCharsets.UTF_8);

    // 1e7cffb80e71c26369bf479f37736f7e
    public static final byte[] input_64_bytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901".getBytes(StandardCharsets.UTF_8);

    // b5ad31712f8d73f590014f172fcaae86
    public static final byte[] input_70_bytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901234567".getBytes(StandardCharsets.UTF_8);

    public static final String input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


}
