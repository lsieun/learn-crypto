package lsieun.tls.entity.handshake;

import java.io.IOException;

public class ServerKeyExchange extends Handshake {
    public final byte[] data;

    public ServerKeyExchange(byte[] data) {
        super(HandshakeType.SERVER_KEY_EXCHANGE);
        this.data = data;
    }

    @Override
    public byte[] getData() throws IOException {
        return this.data;
    }

    public static ServerKeyExchange fromBytes(byte[] data) {
        return new ServerKeyExchange(data);
    }
}
