package lsieun.tls.entity.handshake.ext;

import java.util.Arrays;

public enum NameType {
    HOST_NAME(0),
    ;

    public final int val;

    NameType(int val) {
        this.val = val;
    }

    public static NameType valueOf(int val) {
        return Arrays.stream(values()).filter(item -> item.val == val).findFirst().get();
    }
}
