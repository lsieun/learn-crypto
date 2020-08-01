package lsieun.tls.entity.handshake.ext;

public class SignatureAlgorithms extends Extension {
    public final byte[] content;

    public SignatureAlgorithms(byte[] content) {
        super(ExtensionType.SIGNATURE_ALGORITHMS);
        this.content = content;
    }

    public static SignatureAlgorithms parse(byte[] data) {
        return new SignatureAlgorithms(data);
    }
}
