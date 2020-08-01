package lsieun.crypto.signature.dsa.b_rule;

import lsieun.crypto.signature.dsa.DsaSample;
import lsieun.utils.BigUtils;

import java.math.BigInteger;

// y = g^x % p
public class C_Public_Key {
    public static void main(String[] args) {
        BigInteger private_key = BigUtils.toBigInteger(DsaSample.private_key);
        BigInteger public_key = BigUtils.toBigInteger(DsaSample.public_key);
        BigInteger g = BigUtils.toBigInteger(DsaSample.G);
        BigInteger p = BigUtils.toBigInteger(DsaSample.P);

        BigInteger y = g.modPow(private_key, p);
        System.out.println(public_key.equals(y));
    }
}
