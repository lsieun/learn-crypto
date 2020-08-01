package lsieun.tls.utils;

import lsieun.crypto.hash.updateable.Digest;
import lsieun.crypto.hash.updateable.HashContextFunction;
import lsieun.crypto.sym.BlockOperation;
import lsieun.crypto.sym.modes.CBCUtils;
import lsieun.crypto.sym.modes.ECBUtils;
import lsieun.crypto.sym.OperationType;
import lsieun.crypto.sym.rc4.RC4State;
import lsieun.tls.cipher.*;
import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.alert.Alert;
import lsieun.tls.entity.alert.AlertDescription;
import lsieun.tls.entity.alert.AlertLevel;
import lsieun.tls.entity.handshake.Handshake;
import lsieun.tls.param.ProtectionParameters;
import lsieun.tls.param.TLSParameters;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.io.IOException;
import java.util.Arrays;

public class TLSUtils {

    public static void send_handshake_message(TLSConnection conn, TLSParameters tls_context, Handshake handshake) throws IOException {
        byte[] handshake_bytes = handshake.toBytes();
        send_message(conn, tls_context.active_send_parameters, ContentType.CONTENT_HANDSHAKE, tls_context.protocol_version, handshake_bytes);

        ParameterUtils.update_digest(handshake_bytes, tls_context);
    }

    public static void send_alert_message(TLSConnection conn, TLSParameters tls_context, Alert alert) throws IOException {
        byte[] data = new byte[2];
        data[0] = (byte) alert.level.val;
        data[1] = (byte) alert.description.val;
        send_message(conn, tls_context.active_send_parameters, ContentType.CONTENT_ALERT, tls_context.protocol_version, data);
    }

    /**
     * Send data over an established TLS channel. tls_connect must already
     * have been called with this socket as a parameter.
     */
    public static void tls_send(TLSConnection conn, TLSParameters tls_context, byte[] application_data) throws IOException {
        send_message(conn, tls_context.active_send_parameters, ContentType.CONTENT_APPLICATION_DATA, tls_context.protocol_version, application_data);
    }

    /**
     * Received data from an established TLS channel.
     */
    public static TLSRecord tls_recv(TLSConnection conn, TLSParameters tls_context) throws IOException {
        return receive_message(conn, tls_context.active_recv_parameters);
    }

    /**
     * Orderly shutdown of the TLS channel (note that the socket itself will
     * still be open after this is called).
     */
    public static void tls_shutdown(TLSConnection conn, TLSParameters tls_context) throws IOException {
        Alert alert = new Alert(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        send_alert_message(conn, tls_context, alert);
    }

    public static void send_message(TLSConnection conn, ProtectionParameters parameters, ContentType content_type, ProtocolVersion protocol_version, byte[] content) throws IOException {
        // STEP 1 - display TLS Record
        TLSRecord tls_record = new TLSRecord(content_type, protocol_version, content);
        byte[] data = tls_record.toBytes();
        DisplayUtils.display_record(data, " <-- Client", protocol_version, parameters.suite);

        // STEP 2 - encrypt content
        byte[] encrypted_content = tls_encrypt(tls_record, parameters);
        parameters.seq_num++;

        // STEP 3 - send
        send_tls_record_bytes(conn, content_type, protocol_version, encrypted_content);
    }

    public static TLSRecord receive_message(TLSConnection conn, ProtectionParameters parameters) throws IOException {
        byte[] bytes = receive_tls_record_bytes(conn);

        TLSRecord tls_record = TLSRecord.parse(bytes);

        tls_record = tls_decrypt(tls_record, parameters);
        parameters.seq_num++;

        byte[] data = tls_record.toBytes();

        // STEP 3 - display TLS Record
        DisplayUtils.display_record(data, " <-- Server", tls_record.version, parameters.suite);

        return TLSRecord.parse(data);
    }

    public static TLSRecord tls_decrypt(TLSRecord tls_record, ProtectionParameters parameters) {
        check_cipher_suite(parameters.suite);
        return tls_decrypt(tls_record, parameters.suite, parameters.seq_num, parameters.mac_secret, parameters.key, parameters.iv, parameters.state);
    }

    public static TLSRecord tls_decrypt(TLSRecord tls_record, CipherSuiteIdentifier cipher_suite_id, long seq_num, byte[] mac_secret, byte[] key, byte[] iv, RC4State state) {
        ProtocolVersion protocol_version = tls_record.version;
        switch (protocol_version) {
            case TLSv1_0:
                return TLSUtilsV1_0.tls_decrypt(tls_record, cipher_suite_id, seq_num, mac_secret, key, iv, state);
            case TLSv1_1:
            case TLSv1_2:
                return TLSUtilsV1_1.tls_decrypt(tls_record, cipher_suite_id, seq_num, mac_secret, key, iv, state);
            default:
                throw new RuntimeException("Unsupported TLS Version: " + protocol_version);
        }
    }

    public static byte[] tls_encrypt(TLSRecord tls_record, ProtectionParameters parameters) {
        TLSUtils.check_cipher_suite(parameters.suite);
        return tls_encrypt(tls_record, parameters.suite, parameters.seq_num, parameters.mac_secret, parameters.key, parameters.iv, parameters.state);
    }

    public static byte[] tls_encrypt(TLSRecord tls_record, CipherSuiteIdentifier cipher_suite_id, long seq_num, byte[] mac_secret, byte[] key, byte[] iv, RC4State state) {
        ProtocolVersion protocol_version = tls_record.version;
        switch (protocol_version) {
            case TLSv1_0:
                return TLSUtilsV1_0.tls_encrypt(tls_record, cipher_suite_id, seq_num, mac_secret, key, iv, state);
            case TLSv1_1:
            case TLSv1_2:
                return TLSUtilsV1_1.tls_encrypt(tls_record, cipher_suite_id, seq_num, mac_secret, key, iv, state);
            default:
                throw new RuntimeException("Unsupported TLS Version: " + protocol_version);
        }
    }


    public static byte[] tls_bulk_operate(byte[] input, OperationType operation_type, OperationMode mode, BulkCipherAlgorithm bulk_cipher_algorithm, byte[] key, byte[] iv) {
        int block_size = bulk_cipher_algorithm.block_size;
        BlockOperation block_operation;
        if (operation_type == OperationType.ENCRYPT) {
            block_operation = bulk_cipher_algorithm.bulk_encrypt;
            input = tls_add_padding(input, block_size);
        } else {
            block_operation = bulk_cipher_algorithm.bulk_decrypt;
        }

        byte[] output;
        switch (mode) {
            case ECB:
                output = ECBUtils.ecb_operate(input, key, block_size, block_operation);
                break;
            case CBC:
                output = CBCUtils.cbc_operate(input, key, iv, block_size, block_operation, operation_type);
                break;
            default:
                throw new RuntimeException("Unknown Mode" + mode);
        }

        if (operation_type == OperationType.DECRYPT) {
            output = tls_remove_padding(output);
        }
        return output;

    }

    public static void check_cipher_suite(CipherSuiteIdentifier cipher_suite_id) {
        CipherSuite active_suite = CipherSuite.valueOf(cipher_suite_id);
        BulkCipherAlgorithm bulk_cipher_algorithm = active_suite.bulk_cipher_algorithm;
        CipherType cipher_type = bulk_cipher_algorithm.cipher_type;
        if (cipher_type == CipherType.NULL) {
//            System.out.println("check_cipher_suite No Cipher: " + bulk_cipher_algorithm);
            return;
        }
        if (cipher_type == CipherType.STREAM) {
            switch (bulk_cipher_algorithm) {
                case RC4:
//                    System.out.println("check_cipher_suite Stream Cipher: " + bulk_cipher_algorithm);
                    break;
                default:
                    throw new RuntimeException("Unsupported Stream Cipher: " + bulk_cipher_algorithm);
            }
        } else {
            switch (bulk_cipher_algorithm) {
                case DES:
                case TRIPLE_DES:
                case AES128:
                case AES256:
//                    System.out.println("check_cipher_suite Block Cipher: " + bulk_cipher_algorithm);
                    break;
                default:
                    throw new RuntimeException("Unsupported Block Cipher: " + bulk_cipher_algorithm);
            }
        }
    }

    public static byte[] tls_mac(long seq_num, ContentType content_type, ProtocolVersion protocol_version, byte[] content, byte[] mac_secret, HashContextFunction hash_algorithm) {
        int content_length = content.length;
        int major = protocol_version.major;
        int minor = protocol_version.minor;

        // Allocate enough space for the 8-byte sequence number, the 5-byte pseudo header, and the content.
        byte[] mac_buffer = new byte[13 + content_length];

        // 8-byte sequence number
        byte[] seq_num_bytes = ByteUtils.toBytes(seq_num);
        System.arraycopy(seq_num_bytes, 0, mac_buffer, 0, 8);

        // 5-byte header
        mac_buffer[8] = (byte) content_type.val;
        mac_buffer[9] = (byte) major;
        mac_buffer[10] = (byte) minor;
        mac_buffer[11] = (byte) (content_length >> 8 & 0xFF);
        mac_buffer[12] = (byte) (content_length & 0xFF);

        // content
        System.arraycopy(content, 0, mac_buffer, 13, content_length);

        // hmac
        return Digest.hmac(mac_secret, mac_buffer, hash_algorithm);
    }

    public static byte[] tls_add_padding(byte[] input, int block_size) {
        int input_length = input.length;
        int padding_length = 0;
        if (block_size != 0) {
            padding_length = block_size - (input_length % block_size);
        }

        byte[] output = new byte[input_length + padding_length];
        System.arraycopy(input, 0, output, 0, input_length);
        for (int i = 0; i < padding_length; i++) {
            output[input_length + i] = (byte) (padding_length - 1);
        }
        return output;
    }

    public static byte[] tls_remove_padding(byte[] input) {
        int input_length = input.length;
        int padding_length = input[input_length - 1] + 1;
        int length = input_length - padding_length;
        return Arrays.copyOf(input, length);
    }

    public static void send_tls_record_bytes(TLSConnection conn, ContentType content_type, ProtocolVersion protocol_version, byte[] content) throws IOException {
        // STEP 1 - construct TLS Record
        TLSRecord instance = new TLSRecord(content_type, protocol_version, content);

        // STEP 2 - send TLS Record
        byte[] bytes = instance.toBytes();
        conn.send(bytes);
    }

    public static byte[] receive_tls_record_bytes(TLSConnection conn) throws IOException {
        // STEP 1 - read TLS Record header
        byte[] header = conn.receive(5);
        if (header[0] < ContentType.CONTENT_CHANGE_CIPHER_SPEC.val || header[0] > ContentType.CONTENT_APPLICATION_DATA.val) {
            System.out.println("header: " + HexUtils.format(header, HexFormat.FORMAT_FF_SPACE_FF));
            throw new RuntimeException("content type is not correct: " + header[0]);
        }
        if (header[1] != TLSConst.TLS_VERSION_MAJOR || header[2] != TLSConst.TLS_VERSION_MINOR) {
            System.out.println("Warning: TLS Version may cause failure.");
        }
        int length = (header[3] & 0xFF) << 8 | (header[4] & 0xFF);

        // STEP 2 - read TLS Record content
        byte[] content = conn.receive(length);

        // STEP 3 - return TLS Record
        return ByteUtils.concatenate(header, content);
    }
}
