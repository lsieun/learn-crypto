package lsieun.tls.entity.handshake;

import java.io.IOException;

/**
 * the server hello done message is just a marker and contains no data.
 */
public class ServerHelloDone extends Handshake {
    public ServerHelloDone() {
        super(HandshakeType.SERVER_HELLO_DONE);
    }

    @Override
    public byte[] getData() throws IOException {
        return new byte[0];
    }
}
