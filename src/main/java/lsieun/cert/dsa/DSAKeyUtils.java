package lsieun.cert.dsa;

import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

public class DSAKeyUtils {
    public static DSAPublicKey parse_public_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);

        ASN1Struct asn1_algorithm = asn1_seq.children.get(0);
        ASN1Struct asn1_subject_public_key = asn1_seq.children.get(1);

        ASN1Struct asn1_algorithm_oid = asn1_algorithm.children.get(0);
        ASN1Struct asn1_algorithm_parameters = asn1_algorithm.children.get(1);

        if (!ObjectIdentifier.DSA.equals(asn1_algorithm_oid.data)) {
            throw new RuntimeException("OID is not correct");
        }
        return DSAPublicKey.parse(asn1_algorithm_parameters, asn1_subject_public_key);
    }

    public static DSAPrivateKey parse_private_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        int size = asn1_seq.children.size();
        if (size > 9) {
            throw new RuntimeException("something need to deal with");
        }

        ASN1Struct asn1_version = asn1_seq.children.get(0);
        ASN1Struct asn1_P = asn1_seq.children.get(1);
        ASN1Struct asn1_Q = asn1_seq.children.get(2);
        ASN1Struct asn1_G = asn1_seq.children.get(3);
        ASN1Struct asn1_public = asn1_seq.children.get(4);
        ASN1Struct asn1_private = asn1_seq.children.get(5);

        for (int i = 0; i < size; i++) {
            System.out.println(i + " " + HexUtils.format(asn1_seq.children.get(i).data, HexFormat.FORMAT_FF_SPACE_FF));
        }

        int version = ASN1Converter.toBigInteger(asn1_version).intValue();
        BigInteger P = ASN1Converter.toBigInteger(asn1_P);
        BigInteger Q = ASN1Converter.toBigInteger(asn1_Q);
        BigInteger G = ASN1Converter.toBigInteger(asn1_G);
        BigInteger public_key = ASN1Converter.toBigInteger(asn1_public);
        BigInteger private_key = ASN1Converter.toBigInteger(asn1_private);

        return new DSAPrivateKey(version, P, Q, G, public_key, private_key);
    }
}
