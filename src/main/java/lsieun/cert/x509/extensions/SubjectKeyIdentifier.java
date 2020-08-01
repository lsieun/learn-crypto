package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

public class SubjectKeyIdentifier extends Extension {
    public String key_identifier;

    public SubjectKeyIdentifier(byte[] oid_bytes, boolean critical, byte[] data,
                                String key_identifier) {
        super(oid_bytes, critical, data);
        this.key_identifier = key_identifier;
    }

    public static SubjectKeyIdentifier parse_subject_key_identifier(byte[] oid_bytes, boolean critical, byte[] data) {
        ASN1Struct asn1_key_identifier = ASN1Utils.parse_der(data).get(0);
        String key_identifier = HexUtils.format(asn1_key_identifier.data, HexFormat.FORMAT_FF_SPACE_FF);

        return new SubjectKeyIdentifier(oid_bytes, critical, data, key_identifier);
    }

}
