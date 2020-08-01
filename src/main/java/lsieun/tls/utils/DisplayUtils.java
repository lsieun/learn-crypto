package lsieun.tls.utils;

import lsieun.cert.x509.SignedCertificate;
import lsieun.cert.x509.X509Utils;
import lsieun.tls.cipher.*;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.alert.AlertDescription;
import lsieun.tls.entity.alert.AlertLevel;
import lsieun.tls.entity.handshake.HandshakeType;
import lsieun.tls.entity.handshake.ext.ECPointFormat;
import lsieun.tls.entity.handshake.ext.ExtensionType;
import lsieun.tls.entity.handshake.ext.NameType;
import lsieun.tls.entity.handshake.ext.NamedCurve;
import lsieun.tls.param.TLSParameters;
import lsieun.utils.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Formatter;

public class DisplayUtils {

    public static void display_record(byte[] bytes) {
        display_record(bytes, "", ProtocolVersion.TLSv1_0, CipherSuiteIdentifier.TLS_NULL_WITH_NULL_NULL);
    }

    public static void display_record(byte[] bytes, String suffix, ProtocolVersion protocol_version, CipherSuiteIdentifier cipher_suite_id) {
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
                process_content_change_cipher_spec(bd, fm);
                break;
            case CONTENT_ALERT:
                process_content_alert(bd, fm);
                break;
            case CONTENT_HANDSHAKE:
                process_content_handshake(bd, fm, protocol_version, cipher_suite_id);
                break;
            case CONTENT_APPLICATION_DATA:
                process_content_application_data(bd, fm, length);
                break;
            default:
                throw new RuntimeException("Unknown Content Type: " + content_type_hex);
        }

        process_remaining(bd, fm);
        System.out.println(sb.toString());
    }

    public static void process_remaining(ByteDashboard bd, Formatter fm) {
        int remaining = bd.remaining();
        if (remaining > 0) {
            byte[] remaining_bytes = bd.nextN(remaining);
            String remaining_hex = HexUtils.format(remaining_bytes, " ", 16);
            fm.format("Remaining Bytes: %s%n%n", remaining_hex);
        }
    }

    public static void process_content_change_cipher_spec(ByteDashboard bd, Formatter fm) {
        byte[] change_cipher_spec_message_bytes = bd.nextN(1);
        String change_cipher_spec_message_hex = HexUtils.format(change_cipher_spec_message_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        fm.format("Change Cipher Spec Message (%s)%n", change_cipher_spec_message_hex);
    }

    public static void process_content_alert(ByteDashboard bd, Formatter fm) {
        byte[] alert_level_bytes = bd.nextN(1);
        byte[] alert_description_bytes = bd.nextN(1);

        String alert_level_hex = HexUtils.format(alert_level_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String alert_description_hex = HexUtils.format(alert_description_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        AlertLevel alert_level = AlertLevel.valueOf(ByteUtils.toInt(alert_level_bytes));
        AlertDescription alert_description = AlertDescription.valueOf(ByteUtils.toInt(alert_description_bytes));

        fm.format("Alert Level: %s (%s)%n", alert_level, alert_level_hex);
        fm.format("Alert Description: %s (%s)%n", alert_description, alert_description_hex);
    }

    public static void process_content_handshake(ByteDashboard bd, Formatter fm, ProtocolVersion protocol_version, CipherSuiteIdentifier cipher_suite_id) {
        int count = 0;
        while (bd.hasNext()) {
            if (count > 0) {
                fm.format("%n");
            }
            byte[] length_bytes = bd.peekN(1, 3);
            int length = ByteUtils.toInt(length_bytes);
            byte[] bytes = bd.nextN(length + 4);
            process_content_handshake(bytes, fm, protocol_version, cipher_suite_id);
            count++;
        }
    }

    public static void process_content_handshake(byte[] bytes, Formatter fm, ProtocolVersion protocol_version, CipherSuiteIdentifier cipher_suite_id) {
        int handshake_type_val = bytes[0];
        HandshakeType handshake_type = HandshakeType.valueOf(handshake_type_val);

        switch (handshake_type) {
            case CLIENT_HELLO:
                process_client_hello(bytes, fm);
                break;
            case SERVER_HELLO:
                process_server_hello(bytes, fm);
                break;
            case CERTIFICATE:
                process_certificate(bytes, fm);
                break;
            case SERVER_KEY_EXCHANGE:
                process_server_key_exchange(bytes, fm, protocol_version, cipher_suite_id);
                break;
            case SERVER_HELLO_DONE:
                process_server_hello_done(bytes, fm);
                break;
            case CLIENT_KEY_EXCHANGE:
                process_client_key_exchange(bytes, fm, protocol_version, cipher_suite_id);
                break;
            case FINISHED:
                process_finished(bytes, fm);
                break;
            default:
                throw new RuntimeException("Unsupported handshake type: " + handshake_type);
        }
    }

    public static void process_handshake_header(ByteDashboard bd, Formatter fm) {
        byte[] handshake_type_bytes = bd.nextN(1);
        byte[] length_bytes = bd.nextN(3);

        HandshakeType handshake_type = HandshakeType.valueOf(ByteUtils.toInt(handshake_type_bytes));
        int length = ByteUtils.toInt(length_bytes);

        String handshake_type_hex = HexUtils.format(handshake_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Handshake Type: %s (%s)%n", handshake_type, handshake_type_hex);
        fm.format("Length: %d (%s)%n", length, length_hex);
    }

    // region handshake
    public static void process_client_hello(byte[] bytes, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(bytes);

        process_handshake_header(bd, fm);
        byte[] version_bytes = bd.nextN(2);
        ProtocolVersion version = ProtocolVersion.valueOf(version_bytes);
        byte[] gmt_unix_time_bytes = bd.nextN(4);
        long gmt_unix_time = ByteUtils.toInt(gmt_unix_time_bytes);
        long timestamp = gmt_unix_time * 1000;
        Date date = new Date(timestamp);
        byte[] random_bytes = bd.nextN(28);
        byte[] session_id_length_bytes = bd.nextN(1);
        int session_id_length = ByteUtils.toInt(session_id_length_bytes);
        byte[] session_id_bytes = bd.nextN(session_id_length);
        byte[] cipher_suite_length_bytes = bd.nextN(2);
        int cipher_suite_length = ByteUtils.toInt(cipher_suite_length_bytes);


        String version_hex = HexUtils.format(version_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String gmt_unix_time_hex = HexUtils.format(gmt_unix_time_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String random_hex = HexUtils.format(random_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String session_id_length_hex = HexUtils.format(session_id_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String session_id_hex = HexUtils.format(session_id_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String cipher_suite_length_hex = HexUtils.format(cipher_suite_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Version: %s (%s)%n", version, version_hex);
        fm.format("GMT Unix Time: %s (%s)%n", DateUtils.format(date), gmt_unix_time_hex);
        fm.format("Random Bytes: %s%n", random_hex);
        fm.format("Session ID Length: %s (%s)%n", session_id_length, session_id_length_hex);
        fm.format("Session ID: %s%n", session_id_hex);
        fm.format("Cipher Suites Length: %s (%s)%n", cipher_suite_length, cipher_suite_length_hex);

        int cipher_suite_count = cipher_suite_length / 2;
        for (int i = 0; i < cipher_suite_count; i++) {
            byte[] cipher_suite_id_bytes = bd.nextN(2);
            int cipher_suite_value = ByteUtils.toInt(cipher_suite_id_bytes);
            String cipher_suite_id_hex = HexUtils.format(cipher_suite_id_bytes, HexFormat.FORMAT_FF_SPACE_FF);
            CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.valueOf(cipher_suite_value);
            fm.format("    Cipher Suites: %s (%s)%n", cipher_suite_id, cipher_suite_id_hex);
        }

        byte[] compression_method_length_bytes = bd.nextN(1);
        String compression_method_length_hex = HexUtils.format(compression_method_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        int compression_method_length = ByteUtils.toInt(compression_method_length_bytes);
        fm.format("Compression Methods Length: %s (%s)%n", compression_method_length, compression_method_length_hex);

        for (int i = 0; i < compression_method_length; i++) {
            byte[] compression_method_bytes = bd.nextN(1);
            int compression_method = ByteUtils.toInt(compression_method_bytes);
            String compression_method_hex = HexUtils.format(compression_method_bytes, HexFormat.FORMAT_FF_SPACE_FF);
            fm.format("    Compression Method: %s (%s)%n", compression_method, compression_method_hex);
        }

        display_extensions(bd, fm);
        process_remaining(bd, fm);
    }

    public static void process_server_hello(byte[] bytes, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);

        byte[] version_bytes = bd.nextN(2);
        ProtocolVersion version = ProtocolVersion.valueOf(version_bytes);
        byte[] gmt_unix_time_bytes = bd.nextN(4);
        long gmt_unix_time = ByteUtils.toInt(gmt_unix_time_bytes);
        long timestamp = gmt_unix_time * 1000;
        Date date = new Date(timestamp);
        byte[] random_bytes = bd.nextN(28);
        byte[] session_id_length_bytes = bd.nextN(1);
        int session_id_length = ByteUtils.toInt(session_id_length_bytes);
        byte[] session_id_bytes = bd.nextN(session_id_length);
        byte[] cipher_suite_bytes = bd.nextN(2);
        CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.valueOf(ByteUtils.toInt(cipher_suite_bytes));
        byte[] compression_method_bytes = bd.nextN(1);
        int compression_method = ByteUtils.toInt(compression_method_bytes);

        String version_hex = HexUtils.format(version_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String gmt_unix_time_hex = HexUtils.format(gmt_unix_time_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String random_hex = HexUtils.format(random_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String session_id_length_hex = HexUtils.format(session_id_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String session_id_hex = HexUtils.format(session_id_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String cipher_suite_hex = HexUtils.format(cipher_suite_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String compression_method_hex = HexUtils.format(compression_method_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Version: %s (%s)%n", version, version_hex);
        fm.format("GMT Unix Time: %s/%s (%s)%n", DateUtils.format(date), gmt_unix_time, gmt_unix_time_hex);
        fm.format("Random Bytes: %s%n", random_hex);
        fm.format("Session ID Length: %s (%s)%n", session_id_length, session_id_length_hex);
        fm.format("Session ID: %s%n", session_id_hex);
        fm.format("Cipher Suite: %s (%s)%n", cipher_suite_id, cipher_suite_hex);
        fm.format("Compression Method: %s (%s)%n", compression_method, compression_method_hex);

        display_extensions(bd, fm);
        process_remaining(bd, fm);
    }

    public static void process_certificate(byte[] bytes, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);

        byte[] certificates_length_bytes = bd.nextN(3);
        int certificates_length = ByteUtils.toInt(certificates_length_bytes);

        String certificates_length_hex = HexUtils.format(certificates_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        fm.format("Certificates Length: %s (%s)%n", certificates_length, certificates_length_hex);

        byte[] data = bd.nextN(certificates_length);
        parse_multi_certificates(data, fm);
        process_remaining(bd, fm);
    }

    public static void parse_multi_certificates(byte[] data, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(data);
        while (bd.hasNext()) {
            byte[] certificate_length_bytes = bd.nextN(3);
            int certificate_length = ByteUtils.toInt(certificate_length_bytes);

            String certificate_length_hex = HexUtils.format(certificate_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
            fm.format("Certificate Length: %s (%s)%n", certificate_length, certificate_length_hex);

            byte[] cert_bytes = bd.nextN(certificate_length);
            SignedCertificate signed_certificate = X509Utils.parse_x509_certificate(cert_bytes);
            fm.format("Certificate: %s%n", signed_certificate.tbs_certificate.subject.CommonName);
        }
    }

    public static void process_server_key_exchange(byte[] bytes, Formatter fm, ProtocolVersion protocol_version, CipherSuiteIdentifier cipher_suite_id) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);

        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;

        switch (key_exchange) {
            case NULL: {
                break;
            }
            case DHE_RSA: {
                process_server_key_exchange_dhe_rsa(bd, fm, protocol_version);
                break;
            }
            case ECDHE_RSA: {
                break;
            }
            default:
                throw new RuntimeException("Unsupported Key Exchange: " + key_exchange);
        }
        process_remaining(bd, fm);
    }

    public static void parse_ecdhe_tlsv1(ByteDashboard bd, Formatter fm) {
        byte[] curve_type_bytes = bd.nextN(1);
        byte[] named_curve_bytes = bd.nextN(2);
        byte[] public_key_length_bytes = bd.nextN(1);
        int public_key_length = ByteUtils.toInt(public_key_length_bytes);
        byte[] public_key_bytes = bd.nextN(public_key_length);
        byte[] x_bytes = ByteDashboard.readBytes(public_key_bytes, 1, 32);
        byte[] y_bytes = ByteDashboard.readBytes(public_key_bytes, 33, 32);
        BigInteger x = new BigInteger(1, x_bytes);
        BigInteger y = new BigInteger(1, y_bytes);
        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        byte[] signature_bytes = bd.nextN(signature_length);

        String curve_type_hex = HexUtils.format(curve_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String named_curve_hex = HexUtils.format(named_curve_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String public_key_length_hex = HexUtils.format(public_key_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String public_key_hex = HexUtils.format(public_key_bytes, " ", 33);
        String signature_length_hex = HexUtils.format(signature_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String signature_hex = HexUtils.format(signature_bytes, " ", 32);


        fm.format("Curve Type: named_curve (%s)%n", curve_type_hex);
        fm.format("Named Curve: secp256r1 (%s)%n", named_curve_hex);
        fm.format("Pubkey Length: %d (%s)%n", public_key_length, public_key_length_hex);
        fm.format("Pubkey: %s%n", public_key_hex);
        fm.format("    x: %s%n", x);
        fm.format("    y: %s%n", y);
        fm.format("Signature Length: %d (%s)%n", signature_length, signature_length_hex);
        fm.format("Signature: %s%n", signature_hex);
    }

    public static void parse_ecdhe(ByteDashboard bd, Formatter fm) {
        byte[] curve_type_bytes = bd.nextN(1);
        byte[] named_curve_bytes = bd.nextN(2);
        byte[] public_key_length_bytes = bd.nextN(1);
        int public_key_length = ByteUtils.toInt(public_key_length_bytes);
        byte[] public_key_bytes = bd.nextN(public_key_length);
        byte[] hash_algorithm_bytes = bd.nextN(1);
        byte[] signature_algorithm_bytes = bd.nextN(1);
        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        byte[] signature_bytes = bd.nextN(signature_length);

        String curve_type_hex = HexUtils.format(curve_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String named_curve_hex = HexUtils.format(named_curve_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String public_key_length_hex = HexUtils.format(public_key_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String public_key_hex = HexUtils.format(public_key_bytes, " ", 33);
        String hash_algorithm_hex = HexUtils.format(hash_algorithm_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String signature_algorithm_hex = HexUtils.format(signature_algorithm_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String signature_length_hex = HexUtils.format(signature_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String signature_hex = HexUtils.format(signature_bytes, " ", 32);


        fm.format("Curve Type: named_curve (%s)%n", curve_type_hex);
        fm.format("Named Curve: secp256r1 (%s)%n", named_curve_hex);
        fm.format("Pubkey Length: %d (%s)%n", public_key_length, public_key_length_hex);
        fm.format("Pubkey: %s%n", public_key_hex);
        fm.format("Signature Hash Algorithm Hash: SHA256 (%s)%n", hash_algorithm_hex);
        fm.format("Signature Hash Algorithm Signature: RSA (%s)%n", signature_algorithm_hex);
        fm.format("Signature Length: %d (%s)%n", signature_length, signature_length_hex);
        fm.format("Signature: %s%n", signature_hex);
    }

    public static void process_server_key_exchange_dhe_rsa(ByteDashboard bd, Formatter fm, ProtocolVersion protocol_version) {
        switch (protocol_version) {
            case TLSv1_0:
            case TLSv1_1:
                process_server_key_exchange_dhe_rsa_tlsv1_0(bd, fm);
                break;
            case TLSv1_2:
                process_server_key_exchange_dhe_rsa_tlsv1_2(bd, fm);
                break;
            default:
                throw new RuntimeException("Unsupported Protocol Version: " + protocol_version);
        }
    }

    public static void process_server_key_exchange_dhe_rsa_tlsv1_0(ByteDashboard bd, Formatter fm) {
        byte[] p_length_bytes = bd.nextN(2);
        int p_length = ByteUtils.toInt(p_length_bytes);
        String p_length_hex = HexUtils.format(p_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] p_bytes = bd.nextN(p_length);
        String p_hex = HexUtils.format(p_bytes, " ", 32);
        fm.format("    p Length: %d (%s)%n", p_length, p_length_hex);
        fm.format("    p: %s%n", p_hex);

        byte[] g_length_bytes = bd.nextN(2);
        int g_length = ByteUtils.toInt(g_length_bytes);
        String g_length_hex = HexUtils.format(g_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] g_bytes = bd.nextN(g_length);
        String g_hex = HexUtils.format(g_bytes, " ", 32);
        fm.format("    g Length: %d (%s)%n", g_length, g_length_hex);
        fm.format("    g: %s%n", g_hex);

        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        String pub_key_length_hex = HexUtils.format(pub_key_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] pub_key_bytes = bd.nextN(pub_key_length);
        String pub_key_hex = HexUtils.format(pub_key_bytes, " ", 32);
        fm.format("    Pubkey Length: %d (%s)%n", pub_key_length, pub_key_length_hex);
        fm.format("    Pubkey: %s%n", pub_key_hex);

        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        String signature_length_hex = HexUtils.format(signature_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] signature_bytes = bd.nextN(signature_length);
        String signature_hex = HexUtils.format(signature_bytes, " ", 32);
        fm.format("    Signature Length: %d (%s)%n", signature_length, signature_length_hex);
        fm.format("    Signature: %s%n", signature_hex);
    }

    public static void process_server_key_exchange_dhe_rsa_tlsv1_2(ByteDashboard bd, Formatter fm) {
        byte[] p_length_bytes = bd.nextN(2);
        int p_length = ByteUtils.toInt(p_length_bytes);
        String p_length_hex = HexUtils.format(p_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] p_bytes = bd.nextN(p_length);
        String p_hex = HexUtils.format(p_bytes, " ", 32);
        fm.format("    p Length: %d (%s)%n", p_length, p_length_hex);
        fm.format("    p: %s%n", p_hex);

        byte[] g_length_bytes = bd.nextN(2);
        int g_length = ByteUtils.toInt(g_length_bytes);
        String g_length_hex = HexUtils.format(g_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] g_bytes = bd.nextN(g_length);
        String g_hex = HexUtils.format(g_bytes, " ", 32);
        fm.format("    g Length: %d (%s)%n", g_length, g_length_hex);
        fm.format("    g: %s%n", g_hex);

        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        String pub_key_length_hex = HexUtils.format(pub_key_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] pub_key_bytes = bd.nextN(pub_key_length);
        String pub_key_hex = HexUtils.format(pub_key_bytes, " ", 32);
        fm.format("    Pubkey Length: %d (%s)%n", pub_key_length, pub_key_length_hex);
        fm.format("    Pubkey: %s%n", pub_key_hex);


        byte[] hash_algorithm_bytes = bd.nextN(1);
        int hash_algorithm_val = ByteUtils.toInt(hash_algorithm_bytes);
        String hash_algorithm_hex = HexUtils.format(hash_algorithm_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        HashAlgorithm hash_algorithm = HashAlgorithm.valueOf(hash_algorithm_val);
        fm.format("    Hash Algorithm: %s (%s)%n", hash_algorithm, hash_algorithm_hex);

        byte[] signature_algorithm_bytes = bd.nextN(1);
        int signature_algorithm_val = ByteUtils.toInt(signature_algorithm_bytes);
        String signature_algorithm_hex = HexUtils.format(signature_algorithm_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        SignatureAlgorithm signature_algorithm = SignatureAlgorithm.valueOf(signature_algorithm_val);
        fm.format("    Signature Algorithm: %s (%s)%n", signature_algorithm, signature_algorithm_hex);

        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        String signature_length_hex = HexUtils.format(signature_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] signature_bytes = bd.nextN(signature_length);
        String signature_hex = HexUtils.format(signature_bytes, " ", 32);
        fm.format("    Signature Length: %d (%s)%n", signature_length, signature_length_hex);
        fm.format("    Signature: %s%n", signature_hex);
    }

    public static void process_server_hello_done(byte[] bytes, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);
        // Do Nothing
    }

    public static void process_client_key_exchange(byte[] bytes, Formatter fm, ProtocolVersion protocol_version, CipherSuiteIdentifier cipher_suite_id) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);

        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;

        switch (key_exchange) {
            case NULL: {
                break;
            }
            case RSA: {
                process_client_key_exchange_rsa(bd, fm);
                break;
            }
            case DHE_RSA: {
                switch (protocol_version) {
                    case TLSv1_0:
                        process_client_key_exchange_dhe_rsa(bd, fm);
                        break;
                    case TLSv1_1:
                        break;
                    case TLSv1_2:
                        break;
                    case TLSv1_3:
                        break;
                    default:
                        throw new RuntimeException("Unsupported TLS Version: " + protocol_version);
                }
                break;
            }
            case ECDHE_RSA: {
                break;
            }
            default:
                throw new RuntimeException("Unsupported Key Exchange: " + key_exchange);
        }
        process_remaining(bd, fm);
    }

    public static void process_client_key_exchange_rsa(ByteDashboard bd, Formatter fm) {
        byte[] encrypted_pre_master_length_bytes = bd.nextN(2);
        int encrypted_pre_master_length = ByteUtils.toInt(encrypted_pre_master_length_bytes);
        byte[] encrypted_pre_master_bytes = bd.nextN(encrypted_pre_master_length);

        String encrypted_pre_master_length_hex = HexUtils.format(encrypted_pre_master_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String encrypted_pre_master_hex = HexUtils.format(encrypted_pre_master_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Encrypted PreMaster Length: %d (%s)%n", encrypted_pre_master_length, encrypted_pre_master_length_hex);
        fm.format("Encrypted PreMaster: %s%n", encrypted_pre_master_hex);
    }

    public static void process_client_key_exchange_ecdh(ByteDashboard bd, Formatter fm) {
        byte[] public_key_length_bytes = bd.nextN(1);
        int public_key_length = ByteUtils.toInt(public_key_length_bytes);
        String public_key_hex = HexUtils.format(public_key_length_bytes, HexFormat.FORMAT_FF_FF);
        fm.format("PubKey Length: %d (%s)%n", public_key_length, public_key_hex);

        byte[] public_key_bytes = bd.nextN(public_key_length);
        byte[] x_bytes = ByteDashboard.readBytes(public_key_bytes, 1, 32);
        byte[] y_bytes = ByteDashboard.readBytes(public_key_bytes, 33, 32);
        BigInteger x = new BigInteger(1, x_bytes);
        BigInteger y = new BigInteger(1, y_bytes);
        fm.format("    x: %s%n", x);
        fm.format("    y: %s%n", y);
    }

    public static void process_client_key_exchange_dhe_rsa(ByteDashboard bd, Formatter fm) {
        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        String pub_key_length_hex = HexUtils.format(pub_key_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] pub_key_bytes = bd.nextN(pub_key_length);
        String pub_key_hex = HexUtils.format(pub_key_bytes, " ", 32);
        fm.format("    Pubkey Length: %d (%s)%n", pub_key_length, pub_key_length_hex);
        fm.format("    Pubkey: %s%n", pub_key_hex);
    }

    public static void process_finished(byte[] bytes, Formatter fm) {
        ByteDashboard bd = new ByteDashboard(bytes);
        process_handshake_header(bd, fm);

        byte[] verify_data_bytes = bd.nextN(12);

        String verify_data_hex = HexUtils.format(verify_data_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Verify Data: %s%n", verify_data_hex);
        process_remaining(bd, fm);
    }
    // endregion

    // region extensions
    public static void display_extensions(ByteDashboard bd, Formatter fm) {
        if (!bd.hasNext()) return;

        byte[] extensions_length_bytes = bd.nextN(2);
        int extensions_length = ByteUtils.toInt(extensions_length_bytes);
        String extensions_length_hex = HexUtils.format(extensions_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Extensions Length: %d (%s)%n", extensions_length, extensions_length_hex);

        while (bd.hasNext()) {
            byte[] extension_type_bytes = bd.nextN(2);
            int extension_type_val = ByteUtils.toInt(extension_type_bytes);
            ExtensionType extension_type = ExtensionType.valueOf(extension_type_val);
            String extension_type_hex = HexUtils.format(extension_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);

            fm.format("%s%n", extension_type);
            fm.format("    Type: %d (%s)%n", extension_type_val, extension_type_hex);
            switch (extension_type) {
                case SERVER_NAME: {
                    byte[] length_bytes = bd.nextN(2);
                    int length = ByteUtils.toInt(length_bytes);
                    String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Length: %d (%s)%n", length, length_hex);

                    if (length < 1) {
                        break;
                    }

                    byte[] server_name_list_length_bytes = bd.nextN(2);
                    int server_name_list_length = ByteUtils.toInt(server_name_list_length_bytes);
                    String server_name_list_length_hex = HexUtils.format(server_name_list_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Server Name List Length: %d (%s)%n", server_name_list_length, server_name_list_length_hex);

                    byte[] server_name_type_bytes = bd.nextN(1);
                    int server_name_type = ByteUtils.toInt(server_name_type_bytes);
                    String server_name_type_hex = HexUtils.format(server_name_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Server Name Type: %s (%s)%n", NameType.valueOf(server_name_type), server_name_type_hex);

                    byte[] server_name_length_bytes = bd.nextN(2);
                    int server_name_length = ByteUtils.toInt(server_name_length_bytes);
                    String server_name_length_hex = HexUtils.format(server_name_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Server Name Length: %d (%s)%n", server_name_length, server_name_length_hex);

                    byte[] server_name_bytes = bd.nextN(server_name_length);
                    String server_name = new String(server_name_bytes, StandardCharsets.UTF_8);
                    String server_name_hex = HexUtils.format(server_name_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Server Name: %s (%s)%n", server_name, server_name_hex);
                    break;
                }
                case SUPPORTED_GROUPS: {
                    byte[] length_bytes = bd.nextN(2);
                    int length = ByteUtils.toInt(length_bytes);
                    String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Length: %d (%s)%n", length, length_hex);

                    byte[] supported_groups_list_length_bytes = bd.nextN(2);
                    int supported_groups_list_length = ByteUtils.toInt(supported_groups_list_length_bytes);
                    String supported_groups_list_length_hex = HexUtils.format(supported_groups_list_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Supported Groups List Length: %d (%s)%n", supported_groups_list_length, supported_groups_list_length_hex);

                    int count = supported_groups_list_length / 2;
                    for (int i = 0; i < count; i++) {
                        byte[] named_curve_bytes = bd.nextN(2);
                        int named_curve_val = ByteUtils.toInt(named_curve_bytes);
                        NamedCurve named_curve = NamedCurve.valueOf(named_curve_val);
                        String named_curve_hex = HexUtils.format(named_curve_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                        fm.format("    Supported Group: %s (%s)%n", named_curve, named_curve_hex);
                    }
                    break;
                }
                case EC_POINT_FORMATS: {
                    byte[] length_bytes = bd.nextN(2);
                    int length = ByteUtils.toInt(length_bytes);
                    String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Length: %d (%s)%n", length, length_hex);

                    byte[] ec_point_formats_length_bytes = bd.nextN(1);
                    int ec_point_formats_length = ByteUtils.toInt(ec_point_formats_length_bytes);
                    String ec_point_formats_length_hex = HexUtils.format(ec_point_formats_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    EC Point Formats Length: %d (%s)%n", ec_point_formats_length, ec_point_formats_length_hex);

                    int count = ec_point_formats_length;
                    for (int i = 0; i < count; i++) {
                        byte[] ec_point_format_bytes = bd.nextN(1);
                        int ec_point_format_val = ByteUtils.toInt(ec_point_format_bytes);
                        ECPointFormat ec_point_format = ECPointFormat.valueOf(ec_point_format_val);
                        String ec_point_format_hex = HexUtils.format(ec_point_format_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                        fm.format("    EC Point Format: %s (%s)%n", ec_point_format, ec_point_format_hex);
                    }
                    break;
                }
                default: {
                    byte[] length_bytes = bd.nextN(2);
                    int length = ByteUtils.toInt(length_bytes);
                    String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Length: %d (%s)%n", length, length_hex);

                    byte[] content_bytes = bd.nextN(length);
                    String content_hex = HexUtils.format(content_bytes, HexFormat.FORMAT_FF_SPACE_FF);
                    fm.format("    Content: %s%n", content_hex);
                }
            }
        }

    }
    // endregion

    public static void process_content_application_data(ByteDashboard bd, Formatter fm, int length) {
        byte[] data = bd.nextN(length);
        String data_str = new String(data, StandardCharsets.UTF_8);
        fm.format("Application Data: %n");
        fm.format("================================%n");
        fm.format("%s", data_str);
        fm.format("================================%n");
    }

    public static void display_parameters(TLSParameters tls_context) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        fm.format("Client Random: %s%n", HexUtils.format(tls_context.client_random, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Server Random: %s%n", HexUtils.format(tls_context.server_random, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pre Master Secret: %s%n", HexUtils.format(tls_context.pre_master_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Master Secret: %s%n", HexUtils.format(tls_context.master_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Send MAC Secret: %s%n", HexUtils.format(tls_context.active_send_parameters.mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Recv MAC Secret: %s%n", HexUtils.format(tls_context.active_recv_parameters.mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Send Key Secret: %s%n", HexUtils.format(tls_context.active_send_parameters.key, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Recv Key Secret: %s%n", HexUtils.format(tls_context.active_recv_parameters.key, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Send IV Secret: %s%n", HexUtils.format(tls_context.active_send_parameters.iv, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Active Recv IV Secret: %s%n", HexUtils.format(tls_context.active_recv_parameters.iv, HexFormat.FORMAT_FF_SPACE_FF));

        fm.format("Pending Send MAC Secret: %s%n", HexUtils.format(tls_context.pending_send_parameters.mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pending Recv MAC Secret: %s%n", HexUtils.format(tls_context.pending_recv_parameters.mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pending Send Key Secret: %s%n", HexUtils.format(tls_context.pending_send_parameters.key, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pending Recv Key Secret: %s%n", HexUtils.format(tls_context.pending_recv_parameters.key, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pending Send IV Secret: %s%n", HexUtils.format(tls_context.pending_send_parameters.iv, HexFormat.FORMAT_FF_SPACE_FF));
        fm.format("Pending Recv IV Secret: %s%n", HexUtils.format(tls_context.pending_recv_parameters.iv, HexFormat.FORMAT_FF_SPACE_FF));
        System.out.println(sb.toString());
    }
}
