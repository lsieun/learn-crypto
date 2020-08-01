package lsieun.cert.x509;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

@SuppressWarnings("Duplicates")
public class X509CertificateTestPEM {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/rsa/signed_certificate.pem");
        byte[] bytes = PEMUtils.read(filepath);
        SignedCertificate signedCertificate = X509Utils.parse_x509_certificate(bytes);
        X509Utils.display_x509_certificate(signedCertificate);
    }
}
