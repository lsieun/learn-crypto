package lsieun.cert.dsa;

import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.crypto.signature.dsa.DsaParams;

import java.math.BigInteger;
import java.util.Formatter;

public class DSAPublicKey {
    public BigInteger P;
    public BigInteger Q;
    public BigInteger G;
    public BigInteger public_key;

    public DSAPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger public_key) {
        this.P = p;
        this.Q = q;
        this.G = g;
        this.public_key = public_key;
    }

    public DsaParams toParams() {
        return new DsaParams(G, P, Q);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format("DSAPublicKey {%n");
        fm.format("P = %s%n", this.P);
        fm.format("Q = %s%n", this.Q);
        fm.format("G = %s%n", this.G);
        fm.format("pub = %s%n", this.public_key);
        fm.format("}");
        return sb.toString();
    }

    public static DSAPublicKey parse(ASN1Struct asn1_algorithm_parameters, ASN1Struct asn1_subject_public_key) {
        ASN1Struct asn1_P = asn1_algorithm_parameters.children.get(0);
        ASN1Struct asn1_Q = asn1_algorithm_parameters.children.get(1);
        ASN1Struct asn1_G = asn1_algorithm_parameters.children.get(2);

        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_subject_public_key);
        ASN1Struct asn1_pub = ASN1Utils.parse_der(bit_string_data).get(0);

//        System.out.println("P: " + HexUtils.format(asn1_P.data, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Q: " + HexUtils.format(asn1_Q.data, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("G: " + HexUtils.format(asn1_G.data, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("pub: " + HexUtils.format(asn1_pub.data, HexFormat.FORMAT_FF_SPACE_FF));

        BigInteger P = ASN1Converter.toBigInteger(asn1_P);
        BigInteger Q = ASN1Converter.toBigInteger(asn1_Q);
        BigInteger G = ASN1Converter.toBigInteger(asn1_G);
        BigInteger pub = ASN1Converter.toBigInteger(asn1_pub);

        return new DSAPublicKey(P, Q, G, pub);
    }

}
