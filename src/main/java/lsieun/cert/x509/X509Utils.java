package lsieun.cert.x509;

import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.crypto.asym.rsa.RSAUtils;
import lsieun.cert.asn1.ASN1Const;
import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.cert.cst.HashSignatureIdentifier;
import lsieun.cert.rsa.RSAPublicKey;
import lsieun.cert.x509.extensions.*;
import lsieun.crypto.signature.dsa.DsaParams;
import lsieun.crypto.signature.dsa.DsaSignature;
import lsieun.crypto.signature.dsa.DsaUtils;
import lsieun.crypto.signature.dsa_ecc.ECDSAUtils;
import lsieun.crypto.signature.dsa_ecc.EllipticCurve;
import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.*;

import java.math.BigInteger;
import java.util.*;

public class X509Utils {
    public static SignedCertificate parse_x509_certificate(byte[] bytes) {
        // First, read the whole thing into a traversable ASN.1 structure
        ASN1Struct asn1_signed_cert = ASN1Utils.parse_der(bytes).get(0);

        ASN1Struct asn1_tbs_certificate = asn1_signed_cert.children.get(0);
        ASN1Struct asn1_signature_algorithm = asn1_signed_cert.children.get(1);
        ASN1Struct asn1_signature_value = asn1_signed_cert.children.get(2);

        TBSCertificate tbs_certificate = parse_tbs_certificate(asn1_tbs_certificate);
        HashSignatureIdentifier signature_algorithm = parse_signature_algorithm_identifier(asn1_signature_algorithm);
        SignatureValue signature_value = SignatureValue.parse(asn1_signature_value);

        return new SignedCertificate(tbs_certificate, signature_algorithm, signature_value);
    }

    public static TBSCertificate parse_tbs_certificate(ASN1Struct struct) {
        List<ASN1Struct> children = struct.children;
        int size = children.size();

        // Figure out if there’s an explicit version or not
        int index = 0;
        ASN1Struct asn1_version = children.get(index);
        int version;
        if (asn1_version.tag == 0 && asn1_version.tag_class == ASN1Const.ASN1_CONTEXT_SPECIFIC) {
            version = (asn1_version.children.get(0).data[0] & 0xFF) + 1;
            index++;
        }
        else {
            version = 1;
        }

        ASN1Struct asn1_serialNumber = children.get(index);
        String serial_number = HexUtils.format(asn1_serialNumber.data, HexFormat.FORMAT_FF_SPACE_FF);

        index++;
        ASN1Struct asn1_signature = children.get(index);
        HashSignatureIdentifier signature = parse_signature_algorithm_identifier(asn1_signature);

        index++;
        ASN1Struct asn1_issuer = children.get(index);
        Name issuer = Name.parse(asn1_issuer);

        index++;
        ASN1Struct asn1_validity = children.get(index);
        ValidityPeriod validity = ValidityPeriod.parse(asn1_validity);

        index++;
        ASN1Struct asn1_subject = children.get(index);
        Name subject = Name.parse(asn1_subject);

        index++;
        ASN1Struct asn1_subject_public_key = children.get(index);
        PublicKeyInfo public_key_info = PublicKeyInfo.parse(asn1_subject_public_key);

        index++;
        List<Extension> extensions;
        if (index < size) {
            ASN1Struct asn1_extensions = children.get(index);
            extensions = parse_extensions(asn1_extensions);
        }
        else {
            extensions = new ArrayList<>();
        }

        return new TBSCertificate(version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                public_key_info,
                extensions);
    }

    public static HashSignatureIdentifier parse_signature_algorithm_identifier(ASN1Struct struct) {
        byte[] data = struct.children.get(0).data;
        ObjectIdentifier oid = ObjectIdentifier.valueOf(data);
        return HashSignatureIdentifier.valueOf(oid);
    }


    public static List<Extension> parse_extensions(ASN1Struct struct) {
        if (struct.children.size() != 1) {
            throw new RuntimeException("extensions children size = " + struct.children.size());
        }

        List<Extension> list = new ArrayList<>();
        List<ASN1Struct> children = struct.children.get(0).children;
        for (ASN1Struct child : children) {
            Extension extension = Extension.parse(child);
            list.add(extension);
        }
        return list;
    }

    /**
     * An RSA signature is an ASN.1 DER-encoded PKCS-7 structure including
     * the OID of the signature algorithm (again), and the signature value.
     */
    public static boolean validate_certificate_rsa(byte[] bytes, RSAPublicKey rsa_public_key) {
        // 第一步，解析bytes成证书，将证书拆分成tbsCertificate、signatureAlgorithm和signatureValue三部分
        ASN1Struct asn1_certificate = ASN1Utils.parse_der(bytes).get(0);
        ASN1Struct asn1_tbs_certificate = asn1_certificate.children.get(0);
        ASN1Struct asn1_signature_algorithm = asn1_certificate.children.get(1);
        ASN1Struct asn1_signature_value = asn1_certificate.children.get(2);

        // 第二步，获取tbsCertificate的byte表示形式
        byte[] tbs_certificate_bytes = ByteUtils.concatenate(asn1_tbs_certificate.header, asn1_tbs_certificate.data);

        // 第三步，获取证书的签名算法，并计算hash值
        HashSignatureIdentifier algorithm = parse_signature_algorithm_identifier(asn1_signature_algorithm);

        byte[] tbs_certificate_hash_bytes = null;
        switch (algorithm.hid) {
            case MD5:
                tbs_certificate_hash_bytes = MD5Utils.md5_hash(tbs_certificate_bytes);
                break;
            case SHA1:
                tbs_certificate_hash_bytes = SHA1Utils.sha1_hash(tbs_certificate_bytes);
                break;
            case SHA256:
                tbs_certificate_hash_bytes = SHA256Utils.sha256_hash(tbs_certificate_bytes);
                break;
            default:
                throw new RuntimeException("Unknown Algorithm " + algorithm);
        }

        // 第四步，使用RSA公钥解析signatureValue，获取由RSA私钥加密的hash值
        int length = asn1_signature_value.data.length;
        byte[] input = new byte[length - 1];
        for (int i = 1; i < length; i++) {
            input[i - 1] = asn1_signature_value.data[i];
        }

        RSAKey rsa_key = new RSAKey(rsa_public_key.modulus, rsa_public_key.public_exponent);
        byte[] decoded_bytes = RSAUtils.rsa_decrypt(input, rsa_key);
        ASN1Struct pkcs7_signature = ASN1Utils.parse_der(decoded_bytes).get(0);
        byte[] original_hash_bytes = pkcs7_signature.children.get(1).data;

        // 第五步，验证两个hash是否相等
        return Arrays.equals(tbs_certificate_hash_bytes, original_hash_bytes);
    }

    public static boolean validate_signed_data(byte[] bytes, PublicKeyInfo public_key_info) {
        // 第一步，解析bytes成证书，将内容拆分成asn1_main_content、asn1_signature_algorithm和asn1_signature_value三部分
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        ASN1Struct asn1_main_content = asn1_seq.children.get(0);
        ASN1Struct asn1_signature_algorithm = asn1_seq.children.get(1);
        ASN1Struct asn1_signature_value = asn1_seq.children.get(2);

        // 第二步，获取asn1_main_content的byte[]表示形式
        byte[] main_content_bytes = asn1_main_content.toByteArray();

        // 第三步，获取签名算法，计算hash值
        HashSignatureIdentifier signature_algorithm = parse_signature_algorithm_identifier(asn1_signature_algorithm);

        byte[] hash_bytes;
        switch (signature_algorithm.hid) {
            case MD5:
                hash_bytes = MD5Utils.md5_hash(main_content_bytes);
                break;
            case SHA1:
                hash_bytes = SHA1Utils.sha1_hash(main_content_bytes);
                break;
            case SHA256:
                hash_bytes = SHA256Utils.sha256_hash(main_content_bytes);
                break;
            default:
                throw new RuntimeException("Unknown Algorithm " + signature_algorithm);
        }

        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_signature_value);

        switch (signature_algorithm.aid) {
            case RSA:
                byte[] decoded_bytes = RSAUtils.rsa_decrypt(bit_string_data, public_key_info.rsa_public_key.toKey());
                ASN1Struct pkcs7_signature = ASN1Utils.parse_der(decoded_bytes).get(0);
                byte[] original_hash_bytes = pkcs7_signature.children.get(1).data;

                // 第五步，验证两个hash是否相等
                return Arrays.equals(hash_bytes, original_hash_bytes);
            case DSA: {
                ASN1Struct asn1_dsa_signature = ASN1Utils.parse_der(bit_string_data).get(0);
                ASN1Struct asn1_r = asn1_dsa_signature.children.get(0);
                ASN1Struct asn1_s = asn1_dsa_signature.children.get(1);

                BigInteger r = ASN1Converter.toBigInteger(asn1_r);
                BigInteger s = ASN1Converter.toBigInteger(asn1_s);
                DsaSignature dsa_signature = new DsaSignature(r, s);

                DsaParams dsa_params = public_key_info.dsa_public_key.toParams();
                BigInteger public_key = public_key_info.dsa_public_key.public_key;

                return DsaUtils.dsa_verify(dsa_params, public_key, hash_bytes, dsa_signature);
            }
            case ECDSA: {
                ASN1Struct asn1_dsa_signature = ASN1Utils.parse_der(bit_string_data).get(0);
                ASN1Struct asn1_r = asn1_dsa_signature.children.get(0);
                ASN1Struct asn1_s = asn1_dsa_signature.children.get(1);

                BigInteger r = ASN1Converter.toBigInteger(asn1_r);
                BigInteger s = ASN1Converter.toBigInteger(asn1_s);
                DsaSignature dsa_signature = new DsaSignature(r, s);

                EllipticCurve curve;
                switch (public_key_info.ecdsa_public_key.oid) {
                    case prime256v1:
                        curve = EllipticCurve.P256;
                        break;
                    default:
                        throw new RuntimeException("Unknown curve: " + public_key_info.ecdsa_public_key.oid);
                }

                return ECDSAUtils.ecdsa_verify(curve, public_key_info.ecdsa_public_key.public_key, hash_bytes, dsa_signature);
            }
            default:
                throw new RuntimeException("Unsupported Algorithm: " + signature_algorithm.aid);
        }
    }

    public static void display_x509_certificate(SignedCertificate certificate) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format("Certificate details:%n");
        fm.format("Version: %d%n", certificate.tbs_certificate.version);
        fm.format("Serial number: %s%n", certificate.tbs_certificate.serialNumber);
        fm.format("Signature: %s%n", certificate.tbs_certificate.signature);
        fm.format("issuer: %s%n", output_x500_name(certificate.tbs_certificate.issuer));
        fm.format("not before: %s%n", DateUtils.format(certificate.tbs_certificate.validity.notBefore));
        fm.format("not after: %s%n", DateUtils.format(certificate.tbs_certificate.validity.notAfter));
        fm.format("subject: %s%n", output_x500_name(certificate.tbs_certificate.subject));
        fm.format("Public key algorithm: ");

        PublicKeyInfo public_key_info = certificate.tbs_certificate.subjectPublicKeyInfo;

        switch (public_key_info.algorithm) {
            case RSA:
                fm.format("RSA%n");
                fm.format("    modulus: %s%n", public_key_info.rsa_public_key.modulus);
                fm.format("    exponent: %s%n", public_key_info.rsa_public_key.public_exponent);
                break;
            case DSA:
                fm.format("DSA%n");
                fm.format("    P: %s%n", public_key_info.dsa_public_key.P.toString(16));
                fm.format("    Q: %s%n", public_key_info.dsa_public_key.Q.toString(16));
                fm.format("    G: %s%n", public_key_info.dsa_public_key.G.toString(16));
                fm.format("    pub: %s%n", public_key_info.dsa_public_key.public_key.toString(16));
                break;
            case ECDSA:
                fm.format("ECDSA%n");
                fm.format("    curve: %s%n", public_key_info.ecdsa_public_key.oid);
                fm.format("    x: %s%n", public_key_info.ecdsa_public_key.public_key.x.toString(16));
                fm.format("    y: %s%n", public_key_info.ecdsa_public_key.public_key.y.toString(16));
                break;
            default:
                fm.format("???%n");
                break;
        }

        fm.format("Extensions%n");
        for (Extension extension : certificate.tbs_certificate.extensions) {
            if (extension instanceof KeyUsageExtension) {
                KeyUsageExtension ext = (KeyUsageExtension) extension;
                fm.format("    %s:", "KeyUsageExtension");
                if (ext.critical) {
                    fm.format(" Critical");
                }
                if (ext.isDigitalSignature) {
                    fm.format(" DigitalSignature");
                }
                if (ext.isNonRepudiation) {
                    fm.format(" NonRepudiation");
                }
                if (ext.isKeyEncipherment) {
                    fm.format(" KeyEncipherment");
                }
                if (ext.isDataEncipherment) {
                    fm.format(" DataEncipherment");
                }
                if (ext.isKeyAgreement) {
                    fm.format(" KeyAgreement");
                }
                if (ext.isKeyCertSign) {
                    fm.format(" KeyCertSign");
                }
                if (ext.isCRLSign) {
                    fm.format(" CRLSign");
                }
                if (ext.isEncipherOnly) {
                    fm.format(" EncipherOnly");
                }
                if (ext.isDecipherOnly) {
                    fm.format(" DecipherOnly");
                }
            }
            else if (extension instanceof BasicConstraints) {
                BasicConstraints ext = (BasicConstraints) extension;
                fm.format("    %s: %sCA=%s pathLenConstraint=%s", "BasicConstraints", (ext.critical ? "Critical " : ""), ext.ca, ext.path_len_constraint);
            }
            else if (extension instanceof AuthorityKeyIdentifier) {
                AuthorityKeyIdentifier ext = (AuthorityKeyIdentifier) extension;
                fm.format("    %s: %s", "AuthorityKeyIdentifier", ext.key_identifier);
            }
            else if (extension instanceof SubjectKeyIdentifier) {
                SubjectKeyIdentifier ext = (SubjectKeyIdentifier) extension;
                fm.format("    %s: %s", "SubjectKeyIdentifier", ext.key_identifier);
            }
            else if (extension instanceof ExtKeyUsage) {
                ExtKeyUsage ext = (ExtKeyUsage) extension;
                fm.format("    %s: %n", "Extended Key Usage");
                for (String item : ext.key_usage_list) {
                    fm.format("        %s%n", item);
                }
            }
            else if (extension instanceof SubjectAltName) {
                SubjectAltName ext = (SubjectAltName) extension;
                fm.format("    %s:%n", "SubjectAltName");
                for (Pair<String, String> item : ext.values) {
                    fm.format("        %s=%s%n", item.key, item.value);
                }
            }
            else {
                fm.format("    %s:", extension.oid);
                if (extension.critical) {
                    fm.format(" Critical");
                }

            }
            fm.format("%n");
        }

        fm.format("Signature algorithm: %s%n", certificate.signature_algorithm);
        fm.format("Signature Value: %s%n", HexUtils.format(certificate.signature_value.data, HexFormat.FORMAT_FF_SPACE_FF));

        fm.format("%n");
        System.out.println(sb.toString());
    }

    public static String output_x500_name(Name name) {
        return String.format("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/Email=%s",
                name.CountryName, name.StateOrProvinceName, name.LocalityName,
                name.OrganizationName, name.OrganizationUnitName, name.CommonName, name.EmailAddress);
    }
}
