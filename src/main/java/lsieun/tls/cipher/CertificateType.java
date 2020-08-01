package lsieun.tls.cipher;

public enum CertificateType {
    RSA_SIGNED(1),
    DSS_SIGNED(2),
    RSA_FIXED_DH(3),
    DSS_FIXED_DH(4),
    ;
    public final int value;

    CertificateType(int value) {
        this.value = value;
    }
}
