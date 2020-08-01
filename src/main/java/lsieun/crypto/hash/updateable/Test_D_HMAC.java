package lsieun.crypto.hash.updateable;

import lsieun.crypto.hash.hmac.MACSample;
import lsieun.utils.HexUtils;

public class Test_D_HMAC {
    public static void main(String[] args) {
        byte[] key_bytes = MACSample.key_bytes;
        byte[] input = MACSample.data;
        byte[] hmac_bytes = Digest.hmac(key_bytes, input, DigestCtx::new_sha256_digest);
        System.out.println(HexUtils.toHex(hmac_bytes));
    }
}
