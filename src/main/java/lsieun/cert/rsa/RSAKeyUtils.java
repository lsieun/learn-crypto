package lsieun.cert.rsa;

import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

public class RSAKeyUtils {
    public static RSAPublicKey parse_public_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);

        ASN1Struct asn1_algorithm = asn1_seq.children.get(0);
        ASN1Struct asn1_subject_public_key = asn1_seq.children.get(1);

        ASN1Struct asn1_oid = asn1_algorithm.children.get(0);

        if (!ObjectIdentifier.RSAEncryption.equals(asn1_oid.data)) {
            throw new RuntimeException("oid is not correct");
        }

        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_subject_public_key);
        ASN1Struct asn1_public_key = ASN1Utils.parse_der(bit_string_data).get(0);
        ASN1Struct asn1_modulus = asn1_public_key.children.get(0);
        ASN1Struct asn1_pub_exponent = asn1_public_key.children.get(1);
        System.out.println(HexUtils.format(asn1_modulus.data, HexFormat.FORMAT_FF_SPACE_FF));
        System.out.println(HexUtils.format(asn1_pub_exponent.data, HexFormat.FORMAT_FF_SPACE_FF));

        BigInteger modulus = new BigInteger(1, asn1_modulus.data);
        BigInteger public_exponent = new BigInteger(1, asn1_pub_exponent.data);
        return new RSAPublicKey(modulus, public_exponent);
    }


    public static RSAPrivateKey parse_private_key(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        int size = asn1_seq.children.size();
        if (size > 9) {
            throw new RuntimeException("something need to deal with");
        }

        ASN1Struct asn1_version = asn1_seq.children.get(0);
        ASN1Struct asn1_modulus = asn1_seq.children.get(1);
        ASN1Struct asn1_public_exponent = asn1_seq.children.get(2);
        ASN1Struct asn1_private_exponent = asn1_seq.children.get(3);
        ASN1Struct asn1_prime1 = asn1_seq.children.get(4);
        ASN1Struct asn1_prime2 = asn1_seq.children.get(5);
        ASN1Struct asn1_exponent1 = asn1_seq.children.get(6);
        ASN1Struct asn1_exponent2 = asn1_seq.children.get(7);
        ASN1Struct asn1_coefficient = asn1_seq.children.get(8);

//        for (int i=0;i<9;i++) {
//            System.out.println(i + " " + HexUtils.format(asn1_seq.children.get(i).data, HexFormat.FORMAT_FF_SPACE_FF));
//        }

        int version = ASN1Converter.toBigInteger(asn1_version).intValue();
        BigInteger modulus = ASN1Converter.toBigInteger(asn1_modulus);
        BigInteger public_exponent = ASN1Converter.toBigInteger(asn1_public_exponent);
        BigInteger private_exponent = ASN1Converter.toBigInteger(asn1_private_exponent);
        BigInteger prime1 = ASN1Converter.toBigInteger(asn1_prime1);
        BigInteger prime2 = ASN1Converter.toBigInteger(asn1_prime2);
        BigInteger exponent1 = ASN1Converter.toBigInteger(asn1_exponent1);
        BigInteger exponent2 = ASN1Converter.toBigInteger(asn1_exponent2);
        BigInteger coefficient = ASN1Converter.toBigInteger(asn1_coefficient);
        return new RSAPrivateKey(version, modulus, public_exponent, private_exponent,
                prime1, prime2, exponent1, exponent2, coefficient);
    }
}
