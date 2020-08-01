package lsieun.cert.x509;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.cst.AlgorithmIdentifier;
import lsieun.cert.dsa.DSAPublicKey;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.cert.ecdsa.ECDSAPublicKey;
import lsieun.cert.rsa.RSAPublicKey;

import java.util.List;

public class PublicKeyInfo {
    public final AlgorithmIdentifier algorithm;
    public final RSAPublicKey rsa_public_key;
    public final DSAPublicKey dsa_public_key;
    public final ECDSAPublicKey ecdsa_public_key;

    public PublicKeyInfo(AlgorithmIdentifier algorithm,
                         RSAPublicKey rsa_public_key,
                         DSAPublicKey dsa_public_key,
                         ECDSAPublicKey ecdsa_public_key) {
        this.algorithm = algorithm;
        this.rsa_public_key = rsa_public_key;
        this.dsa_public_key = dsa_public_key;
        this.ecdsa_public_key = ecdsa_public_key;
    }

    public PublicKeyInfo(RSAPublicKey rsa_public_key) {
        this(AlgorithmIdentifier.RSA, rsa_public_key, null, null);
    }

    public PublicKeyInfo(DSAPublicKey dsa_public_key) {
        this(AlgorithmIdentifier.DSA, null, dsa_public_key, null);
    }

    public PublicKeyInfo(ECDSAPublicKey ecdsa_public_key) {
        this(AlgorithmIdentifier.ECDSA, null, null, ecdsa_public_key);
    }

    public static PublicKeyInfo parse(ASN1Struct struct) {
        List<ASN1Struct> children = struct.children;
        ASN1Struct asn1_algorithm = children.get(0);
        ASN1Struct asn1_subject_public_key = children.get(1);

        ASN1Struct asn1_algorithm_oid = asn1_algorithm.children.get(0);
        ASN1Struct asn1_algorithm_parameters = asn1_algorithm.children.get(1);

        ObjectIdentifier oid = ObjectIdentifier.valueOf(asn1_algorithm_oid.data);
        AlgorithmIdentifier algorithm = AlgorithmIdentifier.valueOf(oid);

        RSAPublicKey rsa_public_key = null;
        DSAPublicKey dsa_public_key = null;
        ECDSAPublicKey ecdsa_public_key = null;

        switch (algorithm) {
            case RSA:
                rsa_public_key = RSAPublicKey.parse(asn1_subject_public_key);
                break;
            case DSA:
                dsa_public_key = DSAPublicKey.parse(asn1_algorithm_parameters, asn1_subject_public_key);
                break;
            case ECDSA:
                ecdsa_public_key = ECDSAPublicKey.parse(asn1_algorithm_parameters, asn1_subject_public_key);
                break;
            default:
                throw new RuntimeException("Unexpected AlgorithmIdentifier " + algorithm);
        }

        return new PublicKeyInfo(algorithm, rsa_public_key, dsa_public_key, ecdsa_public_key);
    }
}
