package lsieun.tls.cipher;

import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.crypto.hash.updateable.HashContextFunction;

public enum MACAlgorithm {
    NULL(0, null),
    MD5(16, DigestCtx::new_md5_digest),
    SHA1(20, DigestCtx::new_sha1_digest),
    SHA256(32, DigestCtx::new_sha256_digest),
    ;

    public final int hash_size;
    public final HashContextFunction hash_algorithm;

    MACAlgorithm(int hash_size, HashContextFunction hash_algorithm) {
        this.hash_size = hash_size;
        this.hash_algorithm = hash_algorithm;
    }
}
