package lsieun.cert.cst;

import java.util.Arrays;
import java.util.Optional;

public enum AlgorithmIdentifier {
    RSA(ObjectIdentifier.RSAEncryption),
    DH(ObjectIdentifier.DH),
    DSA(ObjectIdentifier.DSA),
    ECDSA(ObjectIdentifier.EC_Public_Key);
    ;

    public final ObjectIdentifier oid;

    AlgorithmIdentifier(ObjectIdentifier oid) {
        this.oid = oid;
    }

    public static AlgorithmIdentifier valueOf(ObjectIdentifier oid) {
        Optional<AlgorithmIdentifier> result = Arrays.stream(values()).filter(item -> item.oid == oid).findFirst();
        if (result.isPresent()) {
            return result.get();
        }
        else {
            throw new RuntimeException("Unknown Algorithm: " + oid);
        }
    }
}
