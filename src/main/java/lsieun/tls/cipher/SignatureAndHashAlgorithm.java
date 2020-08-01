package lsieun.tls.cipher;

public class SignatureAndHashAlgorithm {
    public HashAlgorithm hash;
    public SignatureAlgorithm signature;

    public SignatureAndHashAlgorithm(HashAlgorithm hash, SignatureAlgorithm signature) {
        this.hash = hash;
        this.signature = signature;
    }
}
