package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.utils.Pair;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SubjectAltName extends Extension {
    public List<Pair<String, String>> values;

    public SubjectAltName(byte[] oid_bytes, boolean critical, byte[] data, List<Pair<String, String>> values) {
        super(oid_bytes, critical, data);
        this.values = values;
    }

    public static SubjectAltName parse_subject_alt_name_extension(byte[] oid_bytes, boolean critical, byte[] data) {
        List<ASN1Struct> list = ASN1Utils.parse_der(data);

        List<Pair<String, String>> values = new ArrayList<>();
        for (ASN1Struct item : list.get(0).children) {
            int tag = item.tag;

            Pair<String, String> p;
            switch (tag) {
                case 2:
                    p = new Pair<>("DNSName", new String(item.data, StandardCharsets.UTF_8));
                    break;
                default:
                    throw new RuntimeException("Unknown tag " + tag);
            }
            values.add(p);
        }

        return new SubjectAltName(oid_bytes, critical, data, values);
    }

}
