package lsieun.cert.rsa;

import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;

import java.math.BigInteger;

public class RSAPublicKey {
    public BigInteger modulus;
    public BigInteger public_exponent;

    public RSAPublicKey(BigInteger modulus, BigInteger public_exponent) {
        this.modulus = modulus;
        this.public_exponent = public_exponent;
    }

    public RSAKey toKey() {
        return new RSAKey(modulus, public_exponent);
    }

    public static RSAPublicKey parse(ASN1Struct asn1_subject_public_key) {
        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_subject_public_key);

        ASN1Struct asn1_seq = ASN1Utils.parse_der(bit_string_data).get(0);
        ASN1Struct asn1_modulus = asn1_seq.children.get(0);
        ASN1Struct asn1_public_exponent = asn1_seq.children.get(1);

        BigInteger modulus = ASN1Converter.toBigInteger(asn1_modulus);
        BigInteger public_exponent = ASN1Converter.toBigInteger(asn1_public_exponent);
        return new RSAPublicKey(modulus, public_exponent);
    }
}
