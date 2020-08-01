package lsieun.cert.x509;

import lsieun.cert.cst.AlgorithmIdentifier;
import lsieun.cert.dsa.DSAKeyUtils;
import lsieun.cert.dsa.DSAPrivateKey;
import lsieun.cert.ecdsa.ECDSAKeyUtils;
import lsieun.cert.ecdsa.ECDSAPrivateKey;
import lsieun.cert.rsa.RSAKeyUtils;
import lsieun.cert.rsa.RSAPrivateKey;

public class PrivateKeyInfo {
    public final AlgorithmIdentifier algorithm;
    public final RSAPrivateKey rsa_private_key;
    public final DSAPrivateKey dsa_private_key;
    public final ECDSAPrivateKey ecdsa_private_key;

    public PrivateKeyInfo(RSAPrivateKey rsa_private_key) {
        this(AlgorithmIdentifier.RSA, rsa_private_key, null, null);
    }

    public PrivateKeyInfo(DSAPrivateKey dsa_private_key) {
        this(AlgorithmIdentifier.DSA, null, dsa_private_key, null);
    }

    public PrivateKeyInfo(ECDSAPrivateKey ecdsa_private_key) {
        this(AlgorithmIdentifier.ECDSA, null, null, ecdsa_private_key);
    }

    public PrivateKeyInfo(AlgorithmIdentifier algorithm,
                          RSAPrivateKey rsa_private_key,
                          DSAPrivateKey dsa_private_key,
                          ECDSAPrivateKey ecdsa_private_key) {
        this.algorithm = algorithm;
        this.rsa_private_key = rsa_private_key;
        this.dsa_private_key = dsa_private_key;
        this.ecdsa_private_key = ecdsa_private_key;
    }

    public static PrivateKeyInfo parse(AlgorithmIdentifier algorithm, byte[] bytes) {
        RSAPrivateKey rsa_private_key = null;
        DSAPrivateKey dsa_private_key = null;
        ECDSAPrivateKey ecdsa_private_key = null;
        switch (algorithm) {
            case RSA:
                rsa_private_key = RSAKeyUtils.parse_private_key(bytes);
                break;
            case DSA:
                dsa_private_key = DSAKeyUtils.parse_private_key(bytes);
                break;
            case ECDSA:
                ecdsa_private_key = ECDSAKeyUtils.parse_private_key(bytes);
                break;
            default:
                throw new RuntimeException("Unsupported Algorithm: " + algorithm);
        }
        return new PrivateKeyInfo(algorithm, rsa_private_key, dsa_private_key, ecdsa_private_key);
    }
}
