package lsieun.crypto.asym.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

// https://www.nayuki.io/page/java-biginteger-was-made-for-rsa-cryptography
public class RSA_Raw {
    public static void main(String[] args) {
        // User parameter
        int BIT_LENGTH = 2048;

        // Generate random primes
        Random rand = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH / 2, rand);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH / 2, rand);

        // Calculate products
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));

        // Generate public and private exponents
        BigInteger e;
        do e = new BigInteger(phi.bitLength(), rand);
        while (e.compareTo(BigInteger.ONE) <= 0
                || e.compareTo(phi) >= 0
                || !e.gcd(phi).equals(BigInteger.ONE));
        BigInteger d = e.modInverse(phi);

        System.out.println("e: " + e);
        System.out.println("d: " + d);
        System.out.println("n: " + n);

        // Message encryption
        BigInteger msg = new BigInteger("123456");  // Any integer in the range [0, n)
        BigInteger enc = msg.modPow(e, n);

        // Message decryption
        BigInteger dec = enc.modPow(d, n);
        System.out.println(dec);
    }
}
