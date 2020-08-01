package lsieun.crypto.signature.dsa_ecc;

import lsieun.crypto.asym.ecc.Point;

import java.math.BigInteger;

public class ECCKey {
    public final BigInteger d; // random integer < n; this is the private key
    public final Point Q; // Q = d * G; this is the public key

    public ECCKey(BigInteger d, Point q) {
        this.d = d;
        this.Q = q;
    }

    public ECCKey(BigInteger d, BigInteger x, BigInteger y) {
        this.d = d;
        this.Q = new Point(x, y);
    }
}
