package lsieun.cert.dsa;

import java.math.BigInteger;

public class DSAPrivateKey {
    public int version;
    public BigInteger P;
    public BigInteger Q;
    public BigInteger G;
    public BigInteger public_key;
    public BigInteger private_key;

    public DSAPrivateKey(int version, BigInteger p, BigInteger q, BigInteger g, BigInteger public_key, BigInteger private_key) {
        this.version = version;
        this.P = p;
        this.Q = q;
        this.G = g;
        this.public_key = public_key;
        this.private_key = private_key;
    }
}
