package lsieun.tls.entity.handshake;

import java.io.IOException;

public class Finished extends Handshake {

    public final byte[] data;

    public Finished(byte[] data) {
        super(HandshakeType.FINISHED);
        this.data = data;
    }

    @Override
    public byte[] getData() throws IOException {
        return data;
    }

    public static Finished fromBytes(byte[] data) {
        return new Finished(data);
    }
}
