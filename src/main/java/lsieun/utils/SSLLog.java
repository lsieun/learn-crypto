package lsieun.utils;

import lsieun.cert.x509.SignedCertificate;
import lsieun.cert.x509.X509Utils;
import lsieun.crypto.hash.updateable.Digest;
import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.tls.cipher.CipherSuite;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.cipher.ConnectionEnd;
import lsieun.tls.cipher.KeyExchange;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.alert.AlertDescription;
import lsieun.tls.entity.alert.AlertLevel;
import lsieun.tls.entity.handshake.*;
import lsieun.tls.entity.handshake.ext.ECPointFormat;
import lsieun.tls.entity.handshake.ext.ExtensionType;
import lsieun.tls.entity.handshake.ext.NameType;
import lsieun.tls.entity.handshake.ext.NamedCurve;
import lsieun.tls.param.TLSParameters;
import lsieun.tls.utils.DisplayUtils;
import lsieun.tls.utils.SSLParameters;
import lsieun.tls.utils.SecretUtils;
import lsieun.tls.utils.TLSUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Formatter;
import java.util.List;

public class SSLLog {
    public enum OP {
        READ,
        WRITE
    }

    public static class Entry {
        public final OP op;
        public final byte[] bytes;

        public Entry(OP op, byte[] bytes) {
            this.op = op;
            this.bytes = bytes;
        }
    }

    public final List<String> lines;
    public final int start;
    public final int stop;
    public int index;

    public SSLParameters parameters = new SSLParameters();

    public boolean client_flag = false;
    public boolean server_flag = false;


    public SSLLog(String class_path) {
        String filepath = FileUtils.getFilePath(class_path);
        List<String> lines = FileUtils.readLines(filepath);
        this.lines = lines;
        this.start = 0;
        this.stop = lines.size();
        this.index = 0;
    }

    public void run() {
        Entry entry;
        while ((entry = getRecordEntry()) != null) {
            OP op = entry.op;
            byte[] record_bytes = entry.bytes;
//            System.out.println("record_bytes:");
//            System.out.println(HexUtils.format(record_bytes, " ", 16));
//            System.out.println();

            TLSRecord tls_record = TLSRecord.parse(record_bytes);
            if (client_flag && op == OP.WRITE) {
                tls_record = TLSUtils.tls_decrypt(tls_record, parameters.cipher_suite_id, parameters.client_seq_num, parameters.client_mac_secret, parameters.client_key, parameters.client_iv, parameters.client_state);
                record_bytes = tls_record.toBytes();
                parameters.client_seq_num++;
            }

            if (server_flag && op == OP.READ) {
                tls_record = TLSUtils.tls_decrypt(tls_record, parameters.cipher_suite_id, parameters.server_seq_num, parameters.server_mac_secret, parameters.server_key, parameters.server_iv, parameters.server_state);
                record_bytes = tls_record.toBytes();
                parameters.server_seq_num++;
            }


            ContentType content_type = tls_record.content_type;
            byte[] content = tls_record.content;
            switch (content_type) {
                case CONTENT_CHANGE_CIPHER_SPEC: {
                    if (op == OP.WRITE) {
                        client_flag = true;
                    }
                    if (op == OP.READ) {
                        server_flag = true;
                    }
                    break;
                }
                case CONTENT_HANDSHAKE: {
                    Handshake handshake = Handshake.parse(content);
                    HandshakeType handshake_type = handshake.hand_shake_type;
                    switch (handshake_type) {
                        case CLIENT_HELLO:
                            parameters.client_hello = (ClientHello) handshake;
                            parameters.protocol_version = parameters.client_hello.client_version;
                            break;
                        case SERVER_HELLO:
                            parameters.server_hello = (ServerHello) handshake;
                            parameters.cipher_suite_id = parameters.server_hello.cipher_suite_id;
                            break;
                        case CERTIFICATE:
                            parameters.certificate = (Certificate) handshake;
                            break;
                        case FINISHED:
                            ConnectionEnd connection_end = (op == OP.READ) ? ConnectionEnd.SERVER : ConnectionEnd.CLIENT;
                            byte[] verify_data = SecretUtils.compute_verify_data(connection_end, parameters.protocol_version, parameters.master_secret, parameters.md5_handshake_digest, parameters.sha1_handshake_digest, parameters.sha256_handshake_digest);
                            System.out.println("verify_data:");
                            System.out.println(HexUtils.format(verify_data, " ", 16));
                            System.out.println();
                            break;
                    }

                    Digest.update_digest(parameters.md5_handshake_digest, content);
                    Digest.update_digest(parameters.sha1_handshake_digest, content);
                    Digest.update_digest(parameters.sha256_handshake_digest, content);
                    break;
                }
                case CONTENT_ALERT:
                case CONTENT_APPLICATION_DATA:
                    break;
                default:
                    throw new RuntimeException("Unknown Content Type: " + content_type);
            }
            display_record(op, record_bytes);
        }
    }

    public void reset() {
        this.index = 0;
    }

    public byte[] read_bytes(int first_line, int rows) {
        StringBuilder sb = new StringBuilder();
        for (int r = 0; r < rows; r++) {
            String line = this.lines.get(first_line + r);
            String sub_str = get_hex(line);
            sb.append(sub_str);
        }
        String content = sb.toString();
        return HexUtils.parse(content.replaceAll(" ", ""), HexFormat.FORMAT_FF_FF);
    }

    public Entry getRecordEntry() {
        Entry first_entry = getEntry();
        if (first_entry == null) {
            return null;
        }
        OP op = first_entry.op;
        byte[] bytes = first_entry.bytes;
        int content_length = ((bytes[3] & 0xFF) << 8) | (bytes[4] & 0xFF);
        int record_length = content_length + 5;
        while (bytes.length < record_length) {
            Entry entry = getEntry();
            if (entry.op != op) {
                throw new RuntimeException("op is Not Right!");
            }
            bytes = ByteUtils.concatenate(bytes, entry.bytes);
        }
        return new Entry(op, bytes);
    }

    public Entry getEntry() {
        while (index < stop) {
            String line = this.lines.get(index);
            index++;
            if (line.startsWith("[Raw write]: length =")) {
                byte[] bytes = read_bytes();
                return new Entry(OP.WRITE, bytes);
            }
            else if (line.startsWith("[Raw read]: length =")) {
                byte[] bytes = read_bytes();
                return new Entry(OP.READ, bytes);
            }
            else if (line.startsWith("PreMaster Secret:")) {
                parameters.pre_master_secret = read_bytes();
            }
            else if (line.startsWith("Client Nonce:")) {
                parameters.client_nonce = read_bytes();
            }
            else if (line.startsWith("Server Nonce:")) {
                parameters.server_nonce = read_bytes();
            }
            else if (line.startsWith("Master Secret:")) {
                parameters.master_secret = read_bytes();
            }
            else if (line.startsWith("Client MAC write Secret:")) {
                parameters.client_mac_secret = read_bytes();
            }
            else if (line.startsWith("Server MAC write Secret:")) {
                parameters.server_mac_secret = read_bytes();
            }
            else if (line.startsWith("Client write key:")) {
                parameters.client_key = read_bytes();
            }
            else if (line.startsWith("Server write key:")) {
                parameters.server_key = read_bytes();
            }
            else if (line.startsWith("Client write IV:")) {
                parameters.client_iv = read_bytes();
            }
            else if (line.startsWith("Server write IV:")) {
                parameters.server_iv = read_bytes();
            }
            else {
                // do nothing
            }
        }
        return null;
    }

    public byte[] read_bytes() {
        int max = (0xFF << 8) | 0xFF;
        int i = 0;

        StringBuilder sb = new StringBuilder();
        while (i < max) {
            String line = this.lines.get(index);
            byte[] bytes = new byte[2];
            bytes[0] = (byte) (i >> 8 & 0xFF);
            bytes[1] = (byte) (i & 0xFF);
            String prefix = HexUtils.format(bytes, HexFormat.FORMAT_FF_FF) + ":";
            if (!line.startsWith(prefix)) {
                break;
            }

            String sub_str = get_hex(line);
            sb.append(sub_str);

            i += 16;
            this.index++;
        }
        String content = sb.toString();
        return HexUtils.parse(content.replaceAll(" ", ""), HexFormat.FORMAT_FF_FF);
    }

    public String get_hex(String line) {
        return line.substring(6, 56);
    }

    public static byte[] read_data(String class_path, String rows) {
        String filepath = FileUtils.getFilePath(class_path);
        List<String> lines = FileUtils.readLines(filepath);

        StringBuilder sb = new StringBuilder();
        String[] row_array = rows.split(",");
        for (String row : row_array) {
            String[] array = row.split("-");
            int start = Integer.parseInt(array[0]);
            int stop = Integer.parseInt(array[1]);

            for (int i = start; i <= stop; i++) {
                String line = lines.get(i - 1);
                String sub_str = line.substring(6, 56);
                sb.append(sub_str);
            }
        }

        String content = sb.toString();
        return HexUtils.parse(content.replaceAll(" ", ""), HexFormat.FORMAT_FF_FF);
    }

    public void display_record(OP op, byte[] bytes) {
        String suffix = (op == OP.READ) ? " <-- Server" : " <-- Client";
        System.out.println(HexUtils.format(bytes, " ", 32) + suffix);

        ByteDashboard bd = new ByteDashboard(bytes);
        byte[] content_type_bytes = bd.nextN(1);
        byte[] version_bytes = bd.nextN(2);
        ProtocolVersion version = ProtocolVersion.valueOf(version_bytes);
        byte[] length_bytes = bd.nextN(2);

        ContentType content_type = ContentType.valueOf(ByteUtils.toInt(content_type_bytes));
        int length = ByteUtils.toInt(length_bytes);

        String content_type_hex = HexUtils.format(content_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String version_hex = HexUtils.format(version_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);

        fm.format("Content Type: %s (%s)%n", content_type, content_type_hex);
        fm.format("Version: %s (%s)%n", version, version_hex);
        fm.format("Length: %d (%s)%n", length, length_hex);

        switch (content_type) {
            case CONTENT_CHANGE_CIPHER_SPEC:
                DisplayUtils.process_content_change_cipher_spec(bd, fm);
                break;
            case CONTENT_ALERT:
                DisplayUtils.process_content_alert(bd, fm);
                break;
            case CONTENT_HANDSHAKE:
                DisplayUtils.process_content_handshake(bd, fm, parameters.protocol_version, parameters.cipher_suite_id);
                break;
            case CONTENT_APPLICATION_DATA:
                DisplayUtils.process_content_application_data(bd, fm, length);
                break;
            default:
                throw new RuntimeException("Unknown Content Type: " + content_type_hex);
        }

        int remaining = bd.remaining();
        byte[] remaining_bytes = bd.nextN(remaining);
        String remaining_hex = HexUtils.format(remaining_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        fm.format("Remaining Bytes: %s%n%n", remaining_hex);
        System.out.println(sb.toString());
    }

}
