package lsieun.cert.x509;

import lsieun.cert.cst.HashSignatureIdentifier;
import lsieun.cert.x509.extensions.Extension;

import java.util.List;

public class TBSCertificate {
    public final int version;
    public final String serialNumber; // This can be much longer than a 4-byte long allows
    public final HashSignatureIdentifier signature;
    public final Name issuer;
    public final ValidityPeriod validity;
    public final Name subject;
    public final PublicKeyInfo subjectPublicKeyInfo;
    public final List<Extension> extensions;


    public TBSCertificate(int version,
                          String serialNumber,
                          HashSignatureIdentifier signature,
                          Name issuer,
                          ValidityPeriod validity,
                          Name subject,
                          PublicKeyInfo subjectPublicKeyInfo,
                          List<Extension> extensions) {
        this.version = version;
        this.serialNumber = serialNumber;
        this.signature = signature;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.extensions = extensions;
    }
}
