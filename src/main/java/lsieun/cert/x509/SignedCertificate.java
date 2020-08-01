package lsieun.cert.x509;

import lsieun.cert.cst.HashSignatureIdentifier;

public class SignedCertificate {
    public final TBSCertificate tbs_certificate;
    public final HashSignatureIdentifier signature_algorithm;
    public final SignatureValue signature_value;

    public SignedCertificate(TBSCertificate tbs_certificate,
                             HashSignatureIdentifier signature_algorithm,
                             SignatureValue signature_value) {
        this.tbs_certificate = tbs_certificate;
        this.signature_algorithm = signature_algorithm;
        this.signature_value = signature_value;
    }
}
