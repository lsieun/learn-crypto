package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;

import java.math.BigInteger;
import java.util.List;

public class BasicConstraints extends Extension {
    public boolean ca;
    public String path_len_constraint;


    public BasicConstraints(byte[] oid_bytes, boolean critical, byte[] data,
                            boolean ca, String path_len_constraint) {
        super(oid_bytes, critical, data);
        this.ca = ca;
        this.path_len_constraint = path_len_constraint;
    }

    public static BasicConstraints parse_basic_constraints(byte[] oid_bytes, boolean critical, byte[] data) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(data).get(0);
        if (asn1_seq.tag != 16) {
            throw new RuntimeException("asn1_seq.tag = " + asn1_seq.tag);
        }

        if (asn1_seq.length == 0) {
            return new BasicConstraints(oid_bytes, critical, data, false, "Zero");
        }

        List<ASN1Struct> list = ASN1Utils.parse_der(asn1_seq.data);
        int size = list.size();

        boolean ca = false;
        if (size > 0) {
            ASN1Struct asn1_ca = list.get(0);
            if (asn1_ca.tag == 1 && (asn1_ca.data[0] & 0xFF) == 0xFF) {
                ca = true;
            }
        }

        String path_len_constraint = "No Limit";
        if (size > 1) {
            ASN1Struct asn1_len = list.get(1);
            BigInteger num = new BigInteger(1, asn1_len.data);
            path_len_constraint = num.toString();
        }

        if(size > 2) {
            throw new RuntimeException("I have something to deal with");
        }

        return new BasicConstraints(oid_bytes, critical, data, ca, path_len_constraint);
    }

}
