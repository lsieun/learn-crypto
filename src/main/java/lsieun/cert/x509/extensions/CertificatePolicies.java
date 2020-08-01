package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;

import java.util.List;

public class CertificatePolicies extends Extension {
    public CertificatePolicies(byte[] oid_bytes, boolean critical, byte[] data) {
        super(oid_bytes, critical, data);
    }

    public static CertificatePolicies parse_certificate_policies(byte[] oid_bytes, boolean critical, byte[] data) {
        final List<ASN1Struct> list = ASN1Utils.parse_der(data);
        ASN1Struct asn1_seq = ASN1Utils.parse_der(data).get(0);
        return new CertificatePolicies(oid_bytes, critical, data);
    }

}
