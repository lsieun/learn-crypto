package lsieun.tls.entity.handshake.ext;

import java.util.Arrays;

public enum ECPointFormat {
    UNCOMPRESSED (0),
    ;

    public final int val;

    ECPointFormat(int val) {
        this.val = val;
    }

    public static ECPointFormat valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }
}
