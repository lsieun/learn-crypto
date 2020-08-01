package lsieun.crypto.signature.dsa.b_rule;

import lsieun.crypto.signature.dsa.DsaSample;
import lsieun.utils.BigUtils;

import java.math.BigInteger;

// q is Prime
public class A_Prime {
    public static void main(String[] args) {
        BigInteger q = BigUtils.toBigInteger(DsaSample.Q);
        boolean flag = q.isProbablePrime(10);
        System.out.println(flag);
    }
}
