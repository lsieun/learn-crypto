package lsieun.crypto.asym.dh_ecc;

import lsieun.crypto.asym.ecc.Point;

import java.math.BigInteger;

public class KeyPair {
    public final BigInteger private_key;
    public final Point public_key;

    public KeyPair(BigInteger private_key, Point public_key) {
        this.private_key = private_key;
        this.public_key = public_key;
    }
}
