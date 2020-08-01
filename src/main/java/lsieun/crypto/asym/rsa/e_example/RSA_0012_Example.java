package lsieun.crypto.asym.rsa.e_example;

import java.math.BigInteger;

public class RSA_0012_Example {
    public static final byte[] TestModulus = {
            (byte) 0xC4, (byte) 0xF8, (byte) 0xE9, (byte) 0xE1, (byte) 0x5D, (byte) 0xCA, (byte) 0xDF, (byte) 0x2B,
            (byte) 0x96, (byte) 0xC7, (byte) 0x63, (byte) 0xD9, (byte) 0x81, (byte) 0x00, (byte) 0x6A, (byte) 0x64,
            (byte) 0x4F, (byte) 0xFB, (byte) 0x44, (byte) 0x15, (byte) 0x03, (byte) 0x0A, (byte) 0x16, (byte) 0xED,
            (byte) 0x12, (byte) 0x83, (byte) 0x88, (byte) 0x33, (byte) 0x40, (byte) 0xF2, (byte) 0xAA, (byte) 0x0E,
            (byte) 0x2B, (byte) 0xE2, (byte) 0xBE, (byte) 0x8F, (byte) 0xA6, (byte) 0x01, (byte) 0x50, (byte) 0xB9,
            (byte) 0x04, (byte) 0x69, (byte) 0x65, (byte) 0x83, (byte) 0x7C, (byte) 0x3E, (byte) 0x7D, (byte) 0x15,
            (byte) 0x1B, (byte) 0x7D, (byte) 0xE2, (byte) 0x37, (byte) 0xEB, (byte) 0xB9, (byte) 0x57, (byte) 0xC2,
            (byte) 0x06, (byte) 0x63, (byte) 0x89, (byte) 0x82, (byte) 0x50, (byte) 0x70, (byte) 0x3B, (byte) 0x3F
    };

    public static final byte[] TestPrivateKey = {
            (byte) 0x8a, (byte) 0x7e, (byte) 0x79, (byte) 0xf3, (byte) 0xfb, (byte) 0xfe, (byte) 0xa8, (byte) 0xeb,
            (byte) 0xfd, (byte) 0x18, (byte) 0x35, (byte) 0x1c, (byte) 0xb9, (byte) 0x97, (byte) 0x91, (byte) 0x36,
            (byte) 0xf7, (byte) 0x05, (byte) 0xb4, (byte) 0xd9, (byte) 0x11, (byte) 0x4a, (byte) 0x06, (byte) 0xd4,
            (byte) 0xaa, (byte) 0x2f, (byte) 0xd1, (byte) 0x94, (byte) 0x38, (byte) 0x16, (byte) 0x67, (byte) 0x7a,
            (byte) 0x53, (byte) 0x74, (byte) 0x66, (byte) 0x18, (byte) 0x46, (byte) 0xa3, (byte) 0x0c, (byte) 0x45,
            (byte) 0xb3, (byte) 0x0a, (byte) 0x02, (byte) 0x4b, (byte) 0x4d, (byte) 0x22, (byte) 0xb1, (byte) 0x5a,
            (byte) 0xb3, (byte) 0x23, (byte) 0x62, (byte) 0x2b, (byte) 0x2d, (byte) 0xe4, (byte) 0x7b, (byte) 0xa2,
            (byte) 0x91, (byte) 0x15, (byte) 0xf0, (byte) 0x6e, (byte) 0xe4, (byte) 0x2c, (byte) 0x41
    };

    public static final byte[] TestPublicKey = {0x01, 0x00, 0x01};

    public static final BigInteger n = new BigInteger("3337");
    public static final BigInteger e = new BigInteger("79");
    public static final BigInteger d = new BigInteger("2629"); // 1019, 2629

    public static void main(String[] args) {
        BigInteger msg = new BigInteger("688");  // Any integer in the range [0, n)

        // Message encryption
        BigInteger encrypted_num = msg.modPow(e, n);
        System.out.println(encrypted_num);

        // Message decryption
        BigInteger decrypted_num = encrypted_num.modPow(d, n);
        System.out.println(decrypted_num);
    }
}
