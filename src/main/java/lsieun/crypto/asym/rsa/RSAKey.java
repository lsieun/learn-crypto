package lsieun.crypto.asym.rsa;

import java.math.BigInteger;

public class RSAKey {
    public BigInteger modulus;
    public BigInteger exponent;

    public RSAKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }
}
