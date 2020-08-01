package lsieun.crypto.asym.ecc;

import java.math.BigInteger;

public class ECCUtils {
    public static Point add_points(Point p1, Point p2, BigInteger p) {
        BigInteger x1 = p1.x;
        BigInteger y1 = p1.y;
        BigInteger x2 = p2.x;
        BigInteger y2 = p2.y;

        BigInteger numerator = y2.subtract(y1); // 分子
        BigInteger denominator = x2.subtract(x1); // 分母
        BigInteger lambda = denominator.modInverse(p).multiply(numerator).mod(p);

        BigInteger x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = x1.subtract(x3).multiply(lambda).subtract(y1).mod(p);

        return new Point(x3, y3);
    }

    public static Point double_point(Point p1, BigInteger a, BigInteger p) {
        BigInteger x1 = p1.x;
        BigInteger y1 = p1.y;

        BigInteger cst_2 = BigInteger.valueOf(2);
        BigInteger cst_3 = BigInteger.valueOf(3);

        BigInteger numerator = x1.multiply(x1).multiply(cst_3).add(a); // 分子
        BigInteger denominator = y1.multiply(cst_2); // 分母
        BigInteger lambda = denominator.modInverse(p).multiply(numerator).mod(p);

        BigInteger x3 = lambda.multiply(lambda).subtract(x1).subtract(x1).mod(p);
        BigInteger y3 = x1.subtract(x3).multiply(lambda).subtract(y1).mod(p);

        return new Point(x3, y3);
    }

    public static Point multiply_point(Point p1, BigInteger k, BigInteger a, BigInteger p) {
        Point p3 = null;
        Point dp = p1;

        int bit_length = k.bitLength();
        for (int i = 0; i < bit_length; i++) {
            if(k.testBit(i)) {
                if(p3 == null) {
                    p3 = dp;
                }
                else {
                    p3 = add_points(p3, dp, p);
                }
            }

            // double dp
            dp = double_point(dp, a, p);
        }

        return p3;
    }
}
