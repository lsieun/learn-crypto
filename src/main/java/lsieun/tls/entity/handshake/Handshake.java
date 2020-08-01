package lsieun.tls.entity.handshake;

import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class Handshake {
    public final HandshakeType hand_shake_type;

    public Handshake(HandshakeType hand_shake_type) {
        this.hand_shake_type = hand_shake_type;
    }

    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        bao.write(hand_shake_type.val); // handshake type

        byte[] data = getData();
        int length = data.length;

        bao.write((length >> 16) & 0xFF); // length 24-bits(!)
        bao.write((length >> 8) & 0xFF);
        bao.write(length & 0xFF);

        bao.write(data);
        return bao.toByteArray();
    }

    public abstract byte[] getData() throws IOException;

    public static Handshake parse(byte[] bytes) {
        ByteDashboard bd = new ByteDashboard(bytes);

        HandshakeType hand_shake_type = HandshakeType.valueOf(bd.next());
        int length = ByteUtils.toInt(bd.nextN(3));
        byte[] data = bd.nextN(length);

        switch (hand_shake_type) {
            case CLIENT_HELLO:
                return ClientHello.fromBytes(data);
            case SERVER_HELLO:
                return ServerHello.fromBytes(data);
            case CERTIFICATE:
                return Certificate.fromBytes(data);
            case SERVER_KEY_EXCHANGE:
                return ServerKeyExchange.fromBytes(data);
            case SERVER_HELLO_DONE:
                return new ServerHelloDone();
            case CLIENT_KEY_EXCHANGE:
                return ClientKeyExchange.fromBytes(data);
            case FINISHED:
                return Finished.fromBytes(data);
            default:
                throw new RuntimeException("Unsupported Handshake Type: " + hand_shake_type);
        }
    }

    public static List<Handshake> parse_list(byte[] content) {
        ByteDashboard bd = new ByteDashboard(content);

        List<Handshake> list = new ArrayList<>();
        while (bd.hasNext()) {
            byte[] length_bytes = bd.peekN(1, 3);
            int length = ByteUtils.toInt(length_bytes);
            byte[] bytes = bd.nextN(length + 4);
            Handshake item = parse(bytes);
            list.add(item);
        }
        return list;
    }

}
