package lsieun.crypto.signature.dsa_ecc;

/**
 * <p>ECC parameters</p>
 * <p>数据URL：https://tools.ietf.org/html/rfc4754#section-8.1</p>
 */
public class ECDSASample {

    /**
     * FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
     */
    public static final char[] P = {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /**
     * 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
     */
    public static final char[] b = {
            0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
            0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
            0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
            0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
    };

    /**
     * bit length = 256
     * FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
     */
    public static final char[] q = {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    };

    /**
     * 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
     */
    public static final char[] gx = {
            0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
            0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
            0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
            0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
    };

    /**
     * 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
     */
    public static final char[] gy = {
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
            0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
            0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
            0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    };

    /**
     * <p>key</p>
     * DC51D386 6A15BACD E33D96F9 92FCA99D A7E6EF09 34E70975 59C27F16 14C88A7F
     */
    public static final char[] w = {
            0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD,
            0xE3, 0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D,
            0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7, 0x09, 0x75,
            0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F
    };

    /**
     * 2442A5CC 0ECD015F A3CA31DC 8E2BBC70 BF42D60C BCA20085 E0822CB0 4235E970
     */
    public static final char[] gwx = {
            0X24, 0X42, 0XA5, 0XCC, 0X0E, 0XCD, 0X01, 0X5F,
            0XA3, 0XCA, 0X31, 0XDC, 0X8E, 0X2B, 0XBC, 0X70,
            0XBF, 0X42, 0XD6, 0X0C, 0XBC, 0XA2, 0X00, 0X85,
            0XE0, 0X82, 0X2C, 0XB0, 0X42, 0X35, 0XE9, 0X70
    };

    /**
     * 6FC98BD7 E50211A4 A27102FA 3549DF79 EBCB4BF2 46B80945 CDDFE7D5 09BBFD7D
     */
    public static final char[] gwy = {
            0X6F, 0XC9, 0X8B, 0XD7, 0XE5, 0X02, 0X11, 0XA4,
            0XA2, 0X71, 0X02, 0XFA, 0X35, 0X49, 0XDF, 0X79,
            0XEB, 0XCB, 0X4B, 0XF2, 0X46, 0XB8, 0X09, 0X45,
            0XCD, 0XDF, 0XE7, 0XD5, 0X09, 0XBB, 0XFD, 0X7D
    };

    /**
     * 9E56F509 196784D9 63D1C0A4 01510EE7 ADA3DCC5 DEE04B15 4BF61AF1 D5A6DECE
     */
    public static final char[] k = {
            0X9E, 0X56, 0XF5, 0X09, 0X19, 0X67, 0X84, 0XD9,
            0X63, 0XD1, 0XC0, 0XA4, 0X01, 0X51, 0X0E, 0XE7,
            0XAD, 0XA3, 0XDC, 0XC5, 0XDE, 0XE0, 0X4B, 0X15,
            0X4B, 0XF6, 0X1A, 0XF1, 0XD5, 0XA6, 0XDE, 0XCE
    };

    /**
     * CB28E099 9B9C7715 FD0A80D8 E47A7707 9716CBBF 917DD72E 97566EA1 C066957C
     */
    public static final char[] gkx = {
            0XCB, 0X28, 0XE0, 0X99, 0X9B, 0X9C, 0X77, 0X15,
            0XFD, 0X0A, 0X80, 0XD8, 0XE4, 0X7A, 0X77, 0X07,
            0X97, 0X16, 0XCB, 0XBF, 0X91, 0X7D, 0XD7, 0X2E,
            0X97, 0X56, 0X6E, 0XA1, 0XC0, 0X66, 0X95, 0X7C
    };

    /**
     * 2B57C023 5FB74897 68D058FF 4911C20F DBE71E36 99D91339 AFBB903E E17255DC
     */
    public static final char[] gky = {
            0X2B, 0X57, 0XC0, 0X23, 0X5F, 0XB7, 0X48, 0X97,
            0X68, 0XD0, 0X58, 0XFF, 0X49, 0X11, 0XC2, 0X0F,
            0XDB, 0XE7, 0X1E, 0X36, 0X99, 0XD9, 0X13, 0X39,
            0XAF, 0XBB, 0X90, 0X3E, 0XE1, 0X72, 0X55, 0XDC
    };
}
