package lsieun.crypto.asym.dh;

import java.math.BigInteger;

public class DHTest {
    public static void main(String[] args) {
        BigInteger g = new BigInteger("2");
        BigInteger p = new BigInteger("17");

        DHKey dh_key = new DHKey(g,p);

        BigInteger a = new BigInteger("5");
        BigInteger b = new BigInteger("7");

        BigInteger Ys = DHUtils.dh_agree(dh_key, a);
        BigInteger Yc = DHUtils.dh_agree(dh_key, b);

        BigInteger Zs = DHUtils.dh_finalize(dh_key, Yc, a);
        BigInteger Zc = DHUtils.dh_finalize(dh_key, Ys, b);

        System.out.println(Zs);
        System.out.println(Zc);
    }
}
