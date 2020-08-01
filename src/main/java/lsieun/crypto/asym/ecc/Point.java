package lsieun.crypto.asym.ecc;

import java.math.BigInteger;

public class Point {
    public final BigInteger x;
    public final BigInteger y;

    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    @Override
    public String toString() {
        return "Point {" +
                "x=" + x +
                ", y=" + y +
                '}';
    }
}
