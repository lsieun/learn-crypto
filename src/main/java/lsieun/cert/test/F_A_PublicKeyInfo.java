package lsieun.cert.test;

import lsieun.cert.asn1.PEMUtils;
import lsieun.cert.x509.SignedCertificate;
import lsieun.cert.x509.X509Utils;

public class F_A_PublicKeyInfo {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Workspace/tmp/zhihu.pem";
        byte[] bytes = PEMUtils.read(filepath);
        SignedCertificate certificate = X509Utils.parse_x509_certificate(bytes);
        System.out.println(certificate.tbs_certificate.subjectPublicKeyInfo.rsa_public_key.modulus);
        System.out.println(certificate.tbs_certificate.subjectPublicKeyInfo.rsa_public_key.public_exponent);
    }
}
