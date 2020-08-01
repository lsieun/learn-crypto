package lsieun.crypto.asym.dh_ecc;

import lsieun.crypto.asym.ecc.ECCUtils;
import lsieun.crypto.asym.ecc.Point;

import java.math.BigInteger;

public class DH_ECC {
    public static void main(String[] args) {
        BigInteger p = BigInteger.valueOf(23);
        BigInteger a = BigInteger.valueOf(1);
        BigInteger b = BigInteger.valueOf(1);
        BigInteger gx = BigInteger.valueOf(5);
        BigInteger gy = BigInteger.valueOf(19);
        Point G = new Point(gx, gy);

        BigInteger private_key_A = BigInteger.valueOf(4);
        Point public_key_A = ECCUtils.multiply_point(G, private_key_A, a, p);

        KeyPair A = new KeyPair(private_key_A, public_key_A);

        BigInteger private_key_B = BigInteger.valueOf(2);
        Point public_key_B = ECCUtils.multiply_point(G, private_key_B, a, p);
        KeyPair B = new KeyPair(private_key_B, public_key_B);

        Point target_A = ECCUtils.multiply_point(public_key_B, private_key_A, a, p);
        System.out.println(target_A);

        Point target_B = ECCUtils.multiply_point(public_key_A, private_key_B, a, p);
        System.out.println(target_B);

    }
}
