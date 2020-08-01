package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Const;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Formatter;
import java.util.List;

public class Extension {
    public final String oid;
    public final byte[] oid_bytes;
    public final boolean critical;
    public final byte[] data;

    public Extension(byte[] oid_bytes, boolean critical, byte[] data) {
        this.oid_bytes = oid_bytes;
        this.critical = critical;
        this.data = data;

        this.oid = HexUtils.format(oid_bytes, HexFormat.FORMAT_FF_SPACE_FF);
    }

    //TODO: 如果有一个extension是critical的，但不认识的OID，就应该抛出异常
    public static Extension parse(ASN1Struct struct) {
        List<ASN1Struct> children = struct.children;
        int size = children.size();
        ASN1Struct asn1_extension_id = children.get(0);
        byte[] oid_bytes = asn1_extension_id.data;

        boolean critical;
        ASN1Struct asn1_extension_value;

        if (size == 2) {
            critical = false;
            asn1_extension_value = children.get(1);
        }
        else if (size == 3) {
            ASN1Struct ans1_extension_critical = children.get(1);
            if (ans1_extension_critical.tag != ASN1Const.ASN1_BOOLEAN) {
                throw new RuntimeException("critical tag is 1");
            }
            critical = (ans1_extension_critical.data[0] & 0xFF) == 0xFF;
            asn1_extension_value = children.get(2);
        }
        else {
            throw new RuntimeException("size is not correct!");
        }
        byte[] data = asn1_extension_value.data;


        if (1 == 2) {
            return null;
        }
        // TODO: 分析具体的extension选项
        else if (Arrays.equals(oid_bytes, ExtensionConst.OID_subjectKeyIdentifier)) { // 55 1D 0E
            return SubjectKeyIdentifier.parse_subject_key_identifier(oid_bytes, critical, data);
        }
        else if (Arrays.equals(oid_bytes, ExtensionConst.OID_keyUsage)) { // 55 1D 0F
            return KeyUsageExtension.parse_key_usage_extension(oid_bytes, critical, data);
        }
        else if (Arrays.equals(oid_bytes, ExtensionConst.OID_subjectAltName)) { // 55 1D 11
            return SubjectAltName.parse_subject_alt_name_extension(oid_bytes, critical, data);
        }
        else if (Arrays.equals(oid_bytes, ExtensionConst.OID_basicConstraints)) { // 55 1D 13
            return BasicConstraints.parse_basic_constraints(oid_bytes, critical, data);
        }
        else if (Arrays.equals(asn1_extension_id.data, ExtensionConst.OID_authorityKeyIdentifier)) {
            return AuthorityKeyIdentifier.parse_authority_key_identifier(oid_bytes, critical, data);
        }
        else if (Arrays.equals(asn1_extension_id.data, ExtensionConst.OID_extKeyUsage)) {
            return ExtKeyUsage.parse_ext_key_usage(oid_bytes, critical, data);
        }
        else if (Arrays.equals(asn1_extension_id.data, ExtensionConst.OID_certificatePolicies)) {
            return CertificatePolicies.parse_certificate_policies(oid_bytes, critical, data);
        }
        else {
            if(critical) {
                throw new RuntimeException("Unknown critical extension OID: " + HexUtils.format(asn1_extension_id.data, HexFormat.FORMAT_FF_SPACE_FF));
            }

//            System.out.print("Unknown extension OID:");
//            for (byte b : asn1_extension_id.data) {
//                System.out.printf(" %02X", (b & 0xFF));
//            }
//            System.out.println();
            return new Extension(oid_bytes, critical, asn1_extension_value.data);
        }

    }

    public static String getMessage(String name, byte[] expected_value, byte[] actual_value) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format("%s OID Unexpected%n", name);
        fm.format("Expected Value: %s%n", HexUtils.format(expected_value, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("  Actual Value: %s", HexUtils.format(actual_value, HexFormat.FORMAT_FF_SPACE_FF));
        return sb.toString();
    }

}
