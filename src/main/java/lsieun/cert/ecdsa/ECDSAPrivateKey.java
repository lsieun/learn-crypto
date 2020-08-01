package lsieun.cert.ecdsa;

import lsieun.cert.cst.ObjectIdentifier;

import java.math.BigInteger;

public class ECDSAPrivateKey {
    public int version;
    public BigInteger private_key;
    public BigInteger public_key;
    public ObjectIdentifier oid;

    public ECDSAPrivateKey(int version, BigInteger private_key, BigInteger public_key, ObjectIdentifier oid) {
        this.version = version;
        this.private_key = private_key;
        this.public_key = public_key;
        this.oid = oid;
    }
}
