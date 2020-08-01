package lsieun.cert.rsa;

import lsieun.crypto.asym.rsa.RSAKey;

import java.math.BigInteger;

public class RSAPrivateKey {
    public int version;
    public BigInteger modulus;
    public BigInteger public_exponent;
    public BigInteger private_exponent;
    public BigInteger prime1;
    public BigInteger prime2;
    public BigInteger exponent1;
    public BigInteger exponent2;
    public BigInteger coefficient;
//    public BigInteger otherPrimeInfos   ;

    public RSAPrivateKey(int version,
                         BigInteger modulus, BigInteger public_exponent, BigInteger private_exponent,
                         BigInteger prime1, BigInteger prime2,
                         BigInteger exponent1, BigInteger exponent2, BigInteger coefficient) {
        this.version = version;
        this.modulus = modulus;
        this.public_exponent = public_exponent;
        this.private_exponent = private_exponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
    }

    public RSAKey toKey() {
        return new RSAKey(modulus, private_exponent);
    }
}
