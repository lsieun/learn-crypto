package lsieun.tls.entity;

import lsieun.tls.cst.TLSConst;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

public enum ProtocolVersion {
    TLSv1_0(0x0301),
    TLSv1_1(0x0302),
    TLSv1_2(0x0303),
    TLSv1_3(0x0304),
    ;

    public final int val;
    public final int major;
    public final int minor;

    ProtocolVersion(int major, int minor) {
        this.major = major;
        this.minor = minor;
        this.val = (major & 0xFF) << 8 | (minor & 0xFF);
    }

    ProtocolVersion(int val) {
        this.val = val;
        this.major = val >> 8 & 0xFF;
        this.minor = val & 0xFF;
    }

    public static ProtocolVersion valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }

    public static ProtocolVersion valueOf(byte[] bytes) {
        int val = ByteUtils.toInt(bytes);
        return valueOf(val);
    }

    public static ProtocolVersion valueOf(int major, int minor) {
        int val = (major & 0xFF) << 8 | (minor & 0xFF);
        return valueOf(val);
    }

    public static ProtocolVersion getDefault() {
        return valueOf(TLSConst.TLS_VERSION_MAJOR, TLSConst.TLS_VERSION_MINOR);
    }
}
