package lsieun.crypto.signature.dsa_ecc;

import lsieun.crypto.asym.ecc.ECCUtils;
import lsieun.crypto.signature.dsa.DsaSignature;
import lsieun.crypto.asym.ecc.Point;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.BigUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class ECDSATest {
    public static void main(String[] args) {
        BigInteger p = BigUtils.toBigInteger(ECDSASample.P);
        BigInteger a = new BigInteger("-3");
        BigInteger b = BigUtils.toBigInteger(ECDSASample.b);
        BigInteger q = BigUtils.toBigInteger(ECDSASample.q);
        BigInteger gx = BigUtils.toBigInteger(ECDSASample.gx);
        BigInteger gy = BigUtils.toBigInteger(ECDSASample.gy);

        Point G = new Point(gx, gy);
        EllipticCurve curve = new EllipticCurve(p, a, b, G, q, null);

        // Generate new public key from private key “w” and point “G”
        BigInteger w = BigUtils.toBigInteger(ECDSASample.w);
        Point Q = ECCUtils.multiply_point(G, w, a, p);
        ECCKey A = new ECCKey(w, Q);

        String msg = "abc";
        byte[] input = msg.getBytes(StandardCharsets.UTF_8);
        byte[] hash_bytes = SHA256Utils.sha256_hash(input);

        DsaSignature signature = ECDSAUtils.ecdsa_sign(curve, A.d, hash_bytes);
        System.out.println("R: " + signature.r.toString(16));
        System.out.println("S: " + signature.s.toString(16));

        boolean flag = ECDSAUtils.ecdsa_verify(curve, A.Q, hash_bytes, signature);
        System.out.println(flag);
    }
}
