package lsieun.crypto.asym.dh;

import java.math.BigInteger;

public class DHKey {
    public BigInteger g;
    public BigInteger p;
    public BigInteger Y;

    public DHKey(BigInteger g, BigInteger p) {
        this.p = p;
        this.g = g;
    }
}
