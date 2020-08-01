package lsieun.tls.cipher;

import java.util.Arrays;

public enum CompressionMethod {
    NULL(0),

    ;
    public final int val;

    CompressionMethod(int val) {
        this.val = val;
    }

    public static CompressionMethod valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }
}
