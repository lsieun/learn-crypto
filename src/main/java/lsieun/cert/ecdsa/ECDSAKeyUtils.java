package lsieun.cert.ecdsa;

import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

public class ECDSAKeyUtils {
    public static ECDSAPublicKey parse_public_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);

        ASN1Struct asn1_algorithm = asn1_seq.children.get(0);
        ASN1Struct asn1_subject_public_key = asn1_seq.children.get(1);

        ASN1Struct asn1_algorithm_oid = asn1_algorithm.children.get(0);
        ASN1Struct asn1_algorithm_parameters = asn1_algorithm.children.get(1);

        if (!ObjectIdentifier.EC_Public_Key.equals(asn1_algorithm_oid.data)) {
            throw new RuntimeException("OID is not correct");
        }
        return ECDSAPublicKey.parse(asn1_algorithm_parameters, asn1_subject_public_key);
    }

    public static ECDSAPrivateKey parse_private_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        int size = asn1_seq.children.size();
        if (size > 4) {
            throw new RuntimeException("something need to deal with");
        }

        ASN1Struct asn1_version = asn1_seq.children.get(0);
        ASN1Struct asn1_private_key = asn1_seq.children.get(1);
        ASN1Struct asn1_parameters = asn1_seq.children.get(2);
        ASN1Struct asn1_public_key = asn1_seq.children.get(3);

        int version = ASN1Converter.toBigInteger(asn1_version).intValue();
        BigInteger private_key = new BigInteger(1, asn1_private_key.data);
        ObjectIdentifier oid = ObjectIdentifier.valueOf(asn1_parameters.children.get(0).data);
        BigInteger public_key = new BigInteger(1, asn1_public_key.children.get(0).data);

        System.out.println(HexUtils.toHex(private_key.toByteArray()));
        System.out.println(HexUtils.toHex(public_key.toByteArray()));
        System.out.println(oid);

        return new ECDSAPrivateKey(version, private_key, public_key, oid);
    }

}
