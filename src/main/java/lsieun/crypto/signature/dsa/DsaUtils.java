package lsieun.crypto.signature.dsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class DsaUtils {
    public static DsaSignature dsa_sign(DsaParams params, BigInteger private_key, byte[] hash_bytes) {
        BigInteger g = params.g;
        BigInteger p = params.p;
        BigInteger q = params.q;

        BigInteger k = generate_message_secret(params);

        // r = ( g ^ k % p ) % q
        BigInteger r = g.modPow(k, p).remainder(q);

        // z = hash(message), only approved with SHA
        int nBytes = q.bitLength() / 8;
        if (nBytes < hash_bytes.length) {
            hash_bytes = Arrays.copyOfRange(hash_bytes, 0, nBytes);
        }
        BigInteger z = new BigInteger(1, hash_bytes);

        // s = ( inv(k) * ( z + xr ) ) % q
        BigInteger inv_k = k.modInverse(q);
        BigInteger s = private_key.multiply(r).add(z).multiply(inv_k).mod(q);

        DsaSignature signature = new DsaSignature(r, s);
        return signature;
    }

    public static BigInteger generate_message_secret(DsaParams params) {
        BigInteger q = params.q;
        int bitLength = q.bitLength();
        BigInteger q_minus_1 = q.subtract(BigInteger.ONE);

        BigInteger c = BigInteger.probablePrime(bitLength, new SecureRandom());
        BigInteger k = c.remainder(q_minus_1).add(BigInteger.ONE);
        return k;
    }

    public static boolean dsa_verify(
            DsaParams params,
            BigInteger public_key,
            byte[] hash_bytes,
            DsaSignature signature) {
        BigInteger g = params.g;
        BigInteger p = params.p;
        BigInteger q = params.q;

        BigInteger r = signature.r;
        BigInteger s = signature.s;

        // w = inv(s) % q
        BigInteger w = s.modInverse(q);

        // z = hash(message), truncated to sizeof(q)
        // get the leftmost min(N, outLen) bits of the digest value
        int nBytes = q.bitLength() / 8;
        if (nBytes < hash_bytes.length) {
            hash_bytes = Arrays.copyOfRange(hash_bytes, 0, nBytes);
        }
        BigInteger z = new BigInteger(1, hash_bytes);

        // u1 = (zw) % q
        BigInteger u1 = z.multiply(w).mod(q);

        // u2 = (rw) % q
        BigInteger u2 = (r.multiply(w)).mod(q);

        // v = ( ( ( g^u1) % p * (y^u2) %p ) % p ) % q
        BigInteger t1 = g.modPow(u1, p);
        BigInteger t2 = public_key.modPow(u2, p);
        BigInteger t3 = t1.multiply(t2);
        BigInteger t5 = t3.mod(p);
        BigInteger v = t5.mod(q);

        // Check to see if v & s match
        return r.equals(v);
    }
}
