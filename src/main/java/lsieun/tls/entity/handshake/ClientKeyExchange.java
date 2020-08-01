package lsieun.tls.entity.handshake;

import java.io.IOException;

public class ClientKeyExchange extends Handshake {

    public final byte[] data;

    public ClientKeyExchange(byte[] data) {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
        this.data = data;
    }

    @Override
    public byte[] getData() throws IOException {
        return this.data;
    }

    public static ClientKeyExchange fromBytes(byte[] data) {
        return new ClientKeyExchange(data);
    }
}
