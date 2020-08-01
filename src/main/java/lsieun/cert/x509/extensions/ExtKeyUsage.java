package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;

import java.util.ArrayList;
import java.util.List;

public class ExtKeyUsage extends Extension {
    public List<String> key_usage_list;

    public ExtKeyUsage(byte[] oid_bytes, boolean critical, byte[] data,
                       List<String> key_usage_list) {
        super(oid_bytes, critical, data);
        this.key_usage_list = key_usage_list;
    }

    public static ExtKeyUsage parse_ext_key_usage(byte[] oid_bytes, boolean critical, byte[] data) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(data).get(0);

        List<String> key_usage_list = new ArrayList<>();
        for (ASN1Struct item : asn1_seq.children) {
            ObjectIdentifier oid = ObjectIdentifier.valueOf(item.data);
            key_usage_list.add(oid.toString());
        }

        return new ExtKeyUsage(oid_bytes, critical, data, key_usage_list);
    }

}
