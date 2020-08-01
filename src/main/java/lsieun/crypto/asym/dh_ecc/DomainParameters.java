package lsieun.crypto.asym.dh_ecc;

import lsieun.crypto.asym.ecc.Point;

import java.math.BigInteger;

public class DomainParameters {
    public final BigInteger p;
    public final BigInteger a;
    public final BigInteger b;
    public final Point G;

    public DomainParameters(BigInteger p, BigInteger a, BigInteger b, Point g) {
        this.p = p;
        this.a = a;
        this.b = b;
        this.G = g;
    }
}
