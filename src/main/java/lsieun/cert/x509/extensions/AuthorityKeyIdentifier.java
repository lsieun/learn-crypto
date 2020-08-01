package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.List;


public class AuthorityKeyIdentifier extends Extension {
    public String key_identifier;

    public AuthorityKeyIdentifier(byte[] oid_bytes, boolean critical, byte[] data,
                                  String key_identifier) {
        super(oid_bytes, critical, data);
        this.key_identifier = key_identifier;
    }

    public static AuthorityKeyIdentifier parse_authority_key_identifier(byte[] oid_bytes, boolean critical, byte[] data) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(data).get(0);
        List<ASN1Struct> children = asn1_seq.children;
        int size = children.size();

        if (size > 0) {
            ASN1Struct asn1_key_identifier = children.get(0);
            String key_identifier = HexUtils.format(asn1_key_identifier.data, HexFormat.FORMAT_FF_SPACE_FF);
            return new AuthorityKeyIdentifier(oid_bytes, critical, data, key_identifier);
        }

        if (size >=2) {
            throw new RuntimeException("something is not dealt with");
        }

        return null;
    }

}
