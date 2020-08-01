package lsieun.tls.entity.handshake.ext;

public class RenegotiationInfo extends Extension {
    public final byte[] content;

    public RenegotiationInfo(byte[] content) {
        super(ExtensionType.RENEGOTIATION_INFO);
        this.content = content;
    }

    public static RenegotiationInfo parse(byte[] data) {
        return new RenegotiationInfo(data);
    }

}
