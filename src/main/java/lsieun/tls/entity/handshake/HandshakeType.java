package lsieun.tls.entity.handshake;

import java.util.Arrays;

// 占用1-byte，因此最多可以有256个值：0~255
public enum HandshakeType {
    HELLO_REQUEST(0),
    CLIENT_HELLO(1),
    SERVER_HELLO(2),
    CERTIFICATE(11),
    SERVER_KEY_EXCHANGE(12),
    CERTIFICATE_REQUEST(13),
    SERVER_HELLO_DONE(14),
    CERTIFICATE_VERIFY(15),
    CLIENT_KEY_EXCHANGE(16),
    FINISHED(20),
    CERTIFICATE_URL(21),
    CERTIFICATE_STATUS(22),
    ;

    public final int val;

    HandshakeType(int val) {
        this.val = val;
    }

    public static HandshakeType valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }

    public static void main(String[] args) {
        HandshakeType type = valueOf(20);
        System.out.println(type);
    }
}
