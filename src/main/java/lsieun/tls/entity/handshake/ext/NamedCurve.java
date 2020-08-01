package lsieun.tls.entity.handshake.ext;

import java.util.Arrays;

public enum NamedCurve {
    SECP256R1(23),
    SECP384R1(24),
    SECP521R1(25),
    X25519(29),
    X448(30),
    ;

    public final int val;

    NamedCurve(int val) {
        this.val = val;
    }

    public static NamedCurve valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }
}
