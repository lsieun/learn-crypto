package lsieun.cert.csr;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.x509.Name;
import lsieun.cert.x509.PublicKeyInfo;
import lsieun.cert.cst.HashSignatureIdentifier;
import lsieun.cert.x509.SignatureValue;
import lsieun.cert.x509.X509Utils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.Formatter;

public class CSRUtils {
    public static CertificationRequest parse_csr(byte[] bytes) {
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        ASN1Struct asn1_certification_request_info = asn1_seq.children.get(0);
        ASN1Struct asn1_signature_algorithm = asn1_seq.children.get(1);
        ASN1Struct asn1_signature_value = asn1_seq.children.get(2);

        CertificationRequestInfo certification_request_info = parse_certification_request_info(asn1_certification_request_info);
        HashSignatureIdentifier signature_algorithm = X509Utils.parse_signature_algorithm_identifier(asn1_signature_algorithm);
        SignatureValue signature_value = SignatureValue.parse(asn1_signature_value);

        return new CertificationRequest(certification_request_info, signature_algorithm, signature_value);
    }

    public static CertificationRequestInfo parse_certification_request_info(ASN1Struct asn1_certification_request) {
        int size = asn1_certification_request.children.size();

        // 第一部分，版本号
        ASN1Struct asn1_version = asn1_certification_request.children.get(0);
        int version = ((asn1_version.data[0] & 0xFF) + 1);

        // 第二部分，主体信息（国家、省、市、机构、部门、姓名）
        ASN1Struct asn1_subject = asn1_certification_request.children.get(1);
        Name subject = Name.parse(asn1_subject);

        // 第三部分，公钥信息
        ASN1Struct asn1_subject_public_key = asn1_certification_request.children.get(2);
        PublicKeyInfo subject_public_key_info = PublicKeyInfo.parse(asn1_subject_public_key);

        byte[] data = ByteUtils.concatenate(asn1_certification_request.header, asn1_certification_request.data);
        CertificationRequestInfo info = new CertificationRequestInfo(version, subject, subject_public_key_info, data);

        if (size == 4) {
            // 第四部分，其他信息
            ASN1Struct asn1_attributes = asn1_certification_request.children.get(3);
        }

        return info;
    }

    public static void show(CertificationRequest request) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format("version: %s%n", request.certification_request_info.version);
        fm.format("Certificate Request Info:%n");

        Name subject = request.certification_request_info.subject;
        fm.format("    %s = %s%n", "CountryName", subject.CountryName);
        fm.format("    %s = %s%n", "StateOrProvinceName", subject.StateOrProvinceName);
        fm.format("    %s = %s%n", "LocalityName", subject.LocalityName);
        fm.format("    %s = %s%n", "OrganizationName", subject.OrganizationName);
        fm.format("    %s = %s%n", "OrganizationUnitName", subject.OrganizationUnitName);
        fm.format("    %s = %s%n", "CommonName", subject.CommonName);
        fm.format("    %s = %s%n", "EmailAddress", subject.EmailAddress);

        PublicKeyInfo public_key_info = request.certification_request_info.subject_public_key;

        fm.format("SubjectPublicKeyInfo: %s%n", public_key_info.algorithm);
        switch (public_key_info.algorithm) {
            case RSA:
                fm.format("    modulus: %s%n", public_key_info.rsa_public_key.modulus);
                fm.format("    exponent: %s%n", public_key_info.rsa_public_key.public_exponent);
                break;
            case DSA:
                fm.format("    P: %s%n", public_key_info.dsa_public_key.P.toString(16));
                fm.format("    Q: %s%n", public_key_info.dsa_public_key.Q.toString(16));
                fm.format("    G: %s%n", public_key_info.dsa_public_key.G.toString(16));
                fm.format("    pub: %s%n", public_key_info.dsa_public_key.public_key.toString(16));
                break;
            default:
                throw new RuntimeException("Unexpected Algorithm: " + public_key_info.algorithm);
        }
        fm.format("SignatureAlgorithm: %s%n", request.signature_algorithm);
        fm.format("Signature: %s%n", HexUtils.format(request.signature_value.data, HexFormat.FORMAT_FF_SPACE_FF));


        System.out.println(sb.toString());
    }

}
