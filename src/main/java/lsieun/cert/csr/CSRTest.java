package lsieun.cert.csr;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class CSRTest {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/dsa/certificate_signing_request.pem");
        byte[] bytes = PEMUtils.read(filepath);

        CertificationRequest csr = CSRUtils.parse_csr(bytes);
        CSRUtils.show(csr);

//        RSAPublicKey rsaKey = csr.certification_request_info.subject_public_key.rsa_public_key;
//        boolean flag = X509Utils.validate_certificate_rsa(bytes, rsaKey);
//        System.out.println("Signature Verification: " + flag);

    }
}
