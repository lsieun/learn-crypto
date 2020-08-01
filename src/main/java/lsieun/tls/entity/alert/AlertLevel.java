package lsieun.tls.entity.alert;

import java.util.Arrays;

public enum AlertLevel {
    WARNING(1),
    FATAL(2);

    public final int val;

    AlertLevel(int val) {
        this.val = val;
    }

    public static AlertLevel valueOf(int val) {
        return Arrays.stream(values()).filter(item -> item.val == val).findFirst().get();
    }
}
