package lsieun.crypto.signature.dsa;

import java.math.BigInteger;

public class DsaParams {
    public BigInteger g;
    public BigInteger p;
    public BigInteger q;

    public DsaParams(BigInteger g, BigInteger p, BigInteger q) {
        this.g = g;
        this.p = p;
        this.q = q;
    }
}
