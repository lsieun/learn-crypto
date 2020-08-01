package lsieun.cert.signature;

import lsieun.crypto.asym.rsa.RSAUtils;
import lsieun.cert.asn1.PEMUtils;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.rsa.RSAPublicKey;
import lsieun.cert.x509.SignedCertificate;
import lsieun.cert.x509.X509Utils;
import lsieun.utils.FileUtils;

import java.util.List;

@SuppressWarnings("Duplicates")
public class PKCS7_RSA_SignatureValue {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/rsa/signed_certificate.pem");
        byte[] bytes = PEMUtils.read(filepath);
        SignedCertificate certificate = X509Utils.parse_x509_certificate(bytes);
        RSAPublicKey rsaKey = certificate.tbs_certificate.subjectPublicKeyInfo.rsa_public_key;

        String cert_filepath = FileUtils.getFilePath("cert/rsa/signed_certificate.pem");
        byte[] cert_bytes = PEMUtils.read(cert_filepath);

        parse_signature_value(cert_bytes, rsaKey);
    }

    public static void parse_signature_value(byte[] bytes, RSAPublicKey rsaKey) {
        ASN1Struct certificate = ASN1Utils.parse_der(bytes).get(0);
        ASN1Struct signature_value = certificate.children.get(2);

        byte[] bit_string_data = ASN1Utils.get_bit_string_data(signature_value);

        byte[] decoded_bytes = RSAUtils.rsa_decrypt(bit_string_data, rsaKey.toKey());

        List<ASN1Struct> list = ASN1Utils.parse_der(decoded_bytes);
        ASN1Utils.show_raw(list);
    }
}
