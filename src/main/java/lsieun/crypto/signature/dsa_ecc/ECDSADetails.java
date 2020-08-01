package lsieun.crypto.signature.dsa_ecc;

import lsieun.crypto.asym.ecc.ECCUtils;
import lsieun.crypto.signature.dsa.DsaSignature;
import lsieun.crypto.asym.ecc.Point;
import lsieun.utils.BigUtils;

import java.math.BigInteger;
import java.util.Arrays;

@SuppressWarnings("Duplicates")
public class ECDSADetails {
    public static DsaSignature ecdsa_sign(EllipticCurve params,
                                          BigInteger private_key,
                                          byte[] hash_bytes) {

        char[] K = {
                0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9, 0x63, 0xD1, 0xC0,
                0xA4, 0x01, 0x51, 0x0E, 0xE7, 0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0,
                0x4B, 0x15, 0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
        };

        System.out.println("gx: " + params.G.x.toString(16).toUpperCase());
        System.out.println("gy: " + params.G.y.toString(16).toUpperCase());

        // This should be a random number between 0 and n-1
        BigInteger k = BigUtils.toBigInteger(K);
        System.out.println("k: " + k.toString(16).toUpperCase());

        Point X = ECCUtils.multiply_point(params.G, k, params.a, params.p);
        BigInteger r = X.x.mod(params.n);

        System.out.println("gkx: " + X.x.toString(16).toUpperCase());
        System.out.println("gky: " + X.y.toString(16).toUpperCase());
        System.out.println("r: " + r.toString(16).toUpperCase());


        // z is the L_n leftmost bits of hash - cannot be longer than n
        int nBytes = params.n.bitLength() / 8;
        if (nBytes < hash_bytes.length) {
            hash_bytes = Arrays.copyOfRange(hash_bytes, 0, nBytes);
        }
        BigInteger z = new BigInteger(1, hash_bytes);
        System.out.println("hash: " + z.toString(16).toUpperCase());

        // s = k^-1 ( z + r d_a ) % n
        BigInteger inv_k = k.modInverse(params.n);
        System.out.println("kinv: " + inv_k.toString(16).toUpperCase());

        BigInteger s = private_key.multiply(r).add(z).multiply(inv_k).mod(params.n);
        System.out.println("s: " + s.toString(16).toUpperCase());

        DsaSignature signature = new DsaSignature(r, s);
        return signature;
    }

    public static boolean ecdsa_verify(EllipticCurve params,
                                       Point public_key,
                                       byte[] hash_bytes,
                                       DsaSignature signature) {

        BigInteger r = signature.r;
        BigInteger s = signature.s;

        // w = s^-1 % n
        BigInteger w = s.modInverse(params.n);
        System.out.println("sinv: " + w.toString(16).toUpperCase());

        // z is the L_n leftmost bits of hash - cannot be longer than n
        int nBytes = params.n.bitLength() / 8;
        if (nBytes < hash_bytes.length) {
            hash_bytes = Arrays.copyOfRange(hash_bytes, 0, nBytes);
        }
        BigInteger z = new BigInteger(1, hash_bytes);

        // u1 = zw % n
        BigInteger u1 = z.multiply(w).mod(params.n);
        System.out.println("u: " + u1.toString(16).toUpperCase());

        // u2 = (rw) % q
        BigInteger u2 = r.multiply(w).mod(params.n);
        System.out.println("v: " + u2.toString(16).toUpperCase());

        // (x1,y1) = u1 * G + u2 * Q
        Point G = params.G;
        Point Q = new Point(public_key.x, public_key.y);

        Point p1 = ECCUtils.multiply_point(G, u1, params.a, params.p);
        Point p2 = ECCUtils.multiply_point(Q, u2, params.a, params.p);
        Point p3 = ECCUtils.add_points(p1, p2, params.p);
        System.out.println("gux: " + p1.x.toString(16).toUpperCase());
        System.out.println("guy: " + p1.y.toString(16).toUpperCase());
        System.out.println("gwvx: " + p2.x.toString(16).toUpperCase());
        System.out.println("gwvy: " + p2.y.toString(16).toUpperCase());
        System.out.println("sumx: " + p3.x.toString(16).toUpperCase());
        System.out.println("sumy: " + p3.y.toString(16).toUpperCase());

        // r = x1 % n
        BigInteger v = p3.x.mod(params.n);
        return r.equals(v);
    }
}
