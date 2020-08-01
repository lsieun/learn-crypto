package lsieun.cert.x509;

import lsieun.utils.FileUtils;

public class X509CertificateTestDER {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Workspace/tmp/cert.der";
        byte[] bytes = FileUtils.readBytes(filepath);
        SignedCertificate signedCertificate = X509Utils.parse_x509_certificate(bytes);
        X509Utils.display_x509_certificate(signedCertificate);
    }
}
