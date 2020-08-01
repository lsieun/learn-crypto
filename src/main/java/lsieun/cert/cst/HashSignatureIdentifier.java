package lsieun.cert.cst;

import java.util.Arrays;
import java.util.Optional;

/**
 * <p>
 * 1.2.840.113549.1.1 - PKCS-1
 * </p>
 * https://www.alvestrand.no/objectid/1.2.840.113549.1.1.html
 */
public enum HashSignatureIdentifier {
    MD5_WITH_RSA(ObjectIdentifier.MD5_With_RSA, HashIdentifier.MD5, AlgorithmIdentifier.RSA), // 4
    SHA1_WITH_RSA(ObjectIdentifier.SHA1_With_RSA, HashIdentifier.SHA1, AlgorithmIdentifier.RSA), // 5
    SHA256_WITH_RSA(ObjectIdentifier.SHA256_With_RSA, HashIdentifier.SHA256, AlgorithmIdentifier.RSA), // 11
    SHA256_WITH_DSA(ObjectIdentifier.SHA256_WITH_DSA, HashIdentifier.SHA256, AlgorithmIdentifier.DSA),
    SHA256_WITH_ECDSA(ObjectIdentifier.SHA256_WITH_ECDSA, HashIdentifier.SHA256, AlgorithmIdentifier.ECDSA),
    ;

    public final ObjectIdentifier oid;
    public final HashIdentifier hid;
    public final AlgorithmIdentifier aid;

    HashSignatureIdentifier(ObjectIdentifier oid, HashIdentifier hid, AlgorithmIdentifier aid) {
        this.oid = oid;
        this.hid = hid;
        this.aid = aid;
    }

    public static HashSignatureIdentifier valueOf(ObjectIdentifier oid) {
        Optional<HashSignatureIdentifier> result = Arrays.stream(values()).filter(item -> item.oid == oid).findFirst();
        if (result.isPresent()) {
            return result.get();
        }
        else {
            throw new RuntimeException("Unknown Signature: " + oid);
        }
    }
}
