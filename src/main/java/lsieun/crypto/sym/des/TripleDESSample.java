package lsieun.crypto.sym.des;

import java.nio.charset.StandardCharsets;

public class TripleDESSample {
    public static final byte[] input = "abcdefgh".getBytes(StandardCharsets.UTF_8);
    public static final byte[] key = "twentyfourcharacterinput".getBytes(StandardCharsets.UTF_8);
    public static final byte[] iv = "initialz".getBytes(StandardCharsets.UTF_8);

    public static final byte[] output_cbc = {
            (byte)0xc0, (byte)0xc4, (byte)0x8b, (byte)0xc4,
            (byte)0x7e, (byte)0x87, (byte)0xce, (byte)0x17
    };

    public static final byte[] output_cbc_pkcs5padding = {
            (byte)0xc0, (byte)0xc4, (byte)0x8b, (byte)0xc4,
            (byte)0x7e, (byte)0x87, (byte)0xce, (byte)0x17,
            (byte)0xb0, (byte)0xa2, (byte)0xb2, (byte)0xb5,
            (byte)0x40, (byte)0x12, (byte)0xe8, (byte)0xd5
    };
}
