package lsieun.crypto.signature.dsa;

import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.utils.BigUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class DsaTest {

    public static void main(String[] args) {
        String msg = "abc123";
        byte[] input = msg.getBytes(StandardCharsets.UTF_8);
        byte[] hash_bytes = SHA1Utils.sha1_hash(input);

        DsaParams params = DsaSample.getDSAParams();
        BigInteger x = BigUtils.toBigInteger(DsaSample.private_key);
        BigInteger y = BigUtils.toBigInteger(DsaSample.public_key);

        DsaSignature signature = DsaUtils.dsa_sign(params, x, hash_bytes);

        System.out.println(signature.r);
        System.out.println(signature.s);

        boolean flag = DsaUtils.dsa_verify(params, y, hash_bytes, signature);
        System.out.println(flag);
    }
}
