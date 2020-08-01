package lsieun.crypto.asym.dh;

import java.math.BigInteger;

public class DHUtils {
    public static BigInteger dh_agree(DHKey dh_key, BigInteger e) {
        BigInteger g = dh_key.g;
        BigInteger p = dh_key.p;

        return g.modPow(e, p);
    }

    public static BigInteger dh_finalize(DHKey dh_key, BigInteger Y, BigInteger e) {
        BigInteger p = dh_key.p;

        return Y.modPow(e, p);
    }
}
