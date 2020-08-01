package lsieun.tls.entity;

import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class TLSRecord {
    public final ContentType content_type;
    public final ProtocolVersion version;
    public final byte[] content;

    public TLSRecord(ContentType content_type, byte[] content) {
        this.content_type = content_type;
        this.content = content;
        this.version = ProtocolVersion.getDefault();
    }

    public TLSRecord(ContentType content_type, ProtocolVersion version, byte[] content) {
        this.content_type = content_type;
        this.version = version;
        this.content = content;
    }

    public byte[] getHeader() {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        bao.write(content_type.val);
        bao.write(version.major);
        bao.write(version.minor);

        int length = content.length;
        bao.write((length >> 8) & 0xFF);
        bao.write(length & 0xFF);
        return bao.toByteArray();
    }

    public byte[] toBytes() {
        try {
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            bao.write(content_type.val);
            bao.write(version.major);
            bao.write(version.minor);

            int length = content.length;
            bao.write((length >> 8) & 0xFF);
            bao.write(length & 0xFF);
            bao.write(content);
            return bao.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("TLSPlaintext.toBytes() Exception");
        }
    }

    public static TLSRecord parse(byte[] bytes) {
        ByteDashboard bd = new ByteDashboard(bytes);

        byte content_type_byte = bd.next();
        byte major_byte = bd.next();
        byte minor_byte = bd.next();
        byte[] length_bytes = bd.nextN(2);
        int length = ByteUtils.toInt(length_bytes);
        byte[] content = bd.nextN(length);

        ContentType content_type = ContentType.valueOf(content_type_byte);
        ProtocolVersion version = ProtocolVersion.valueOf(major_byte, minor_byte);
        return new TLSRecord(content_type, version, content);
    }
}
