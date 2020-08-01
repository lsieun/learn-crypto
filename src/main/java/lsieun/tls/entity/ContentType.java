package lsieun.tls.entity;

import java.util.Arrays;

public enum ContentType {
    CONTENT_CHANGE_CIPHER_SPEC(20),
    CONTENT_ALERT(21),
    CONTENT_HANDSHAKE(22),
    CONTENT_APPLICATION_DATA(23);

    public final int val;

    ContentType(int val) {
        this.val = val;
    }

    public static ContentType valueOf(int val) {
        return Arrays.stream(values()).filter(item -> item.val == val).findFirst().get();
    }
}
