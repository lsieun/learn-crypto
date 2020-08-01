package lsieun.crypto.asym.rsa;

import java.math.BigInteger;

public class RSAConst {
    public static BigInteger MINI_E = new BigInteger("79");
    public static BigInteger MINI_D = new BigInteger("1019");
    public static BigInteger MINI_N = new BigInteger("3337");

    public static RSAKey MINI_PUBLIC_KEY = new RSAKey(MINI_N, MINI_E);
    public static RSAKey MINI_PRIVATE_KEY = new RSAKey(MINI_N, MINI_D);

}
