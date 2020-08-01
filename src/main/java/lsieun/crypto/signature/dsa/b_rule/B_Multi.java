package lsieun.crypto.signature.dsa.b_rule;

import lsieun.crypto.signature.dsa.DsaSample;
import lsieun.utils.BigUtils;

import java.math.BigInteger;

// N * q = p - 1
public class B_Multi {
    public static void main(String[] args) {
        BigInteger p = BigUtils.toBigInteger(DsaSample.P);
        BigInteger p_minus_1 = p.subtract(BigInteger.ONE);

        BigInteger q = BigUtils.toBigInteger(DsaSample.Q);

        System.out.println("p: " + p);
        System.out.println(p.bitLength());
        System.out.println("q: " + q);
        System.out.println(q.bitLength());

        BigInteger quotient = p_minus_1.divide(q);
        BigInteger remainder = p_minus_1.remainder(q);
        System.out.println("quotient: " + quotient);
        System.out.println("remainder: " + remainder);

        BigInteger product = quotient.multiply(q);
        System.out.println(product);
        System.out.println(p_minus_1);
    }
}
