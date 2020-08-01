package lsieun.tls.utils;

import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.crypto.asym.rsa.RSAUtils;
import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.tls.cipher.*;
import lsieun.tls.entity.ChangeCipherSpec;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.alert.Alert;
import lsieun.tls.entity.alert.AlertLevel;
import lsieun.tls.entity.handshake.*;
import lsieun.tls.key.DHKeyExchange;
import lsieun.tls.param.ProtectionParameters;
import lsieun.tls.param.TLSParameters;
import lsieun.tls.param.TLSServerParameters;
import lsieun.utils.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class TLSServerUtils {
    public static void tls_accept(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        tls_context.connection_end = ConnectionEnd.SERVER;

        // The client sends the first message
        while (!tls_context.got_client_hello) {
            receive_tls_msg(conn, tls_context);
        }

        if (tls_context.session_id == null) {
            tls_accept_new(conn, tls_context);
        } else {
            tls_resume_old(conn, tls_context);
        }
    }

    public static void tls_accept_new(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        send_server_hello(conn, tls_context);
        send_certificate(conn, tls_context);
        send_server_key_exchange(conn, tls_context);
        send_server_hello_done(conn, tls_context);

        // Now the client should send a client key exchange, change cipher spec, and
        // an encrypted “finalize” message
        while (!tls_context.peer_finished) {
            receive_tls_msg(conn, tls_context);
        }

        send_change_cipher_spec(conn, tls_context);

        // Handshake is complete; now ready to start sending encrypted data
        send_finished(conn, tls_context);

        // IFF the handshake was successful, put it into the session ID cache list for reuse.
        TLSSessionStore.remember_session(tls_context);
    }

    public static void tls_resume_old(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        send_server_hello(conn, tls_context);
        SecretUtils.calculate_keys(tls_context);

        send_change_cipher_spec(conn, tls_context);
        send_finished(conn, tls_context);

        while (!tls_context.peer_finished) {
            receive_tls_msg(conn, tls_context);
        }
    }

    // region send
    public static void send_server_hello(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        byte[] session_id;
        if (tls_context.session_id == null) {
            session_id = TLSSession.generate_new_session_id();
        } else {
            session_id = tls_context.session_id;
        }
        CipherSuiteIdentifier cipher_suite_id = tls_context.pending_send_parameters.suite;
        ServerHello server_hello = ServerHello.getInstance(cipher_suite_id, session_id);

        TLSUtils.send_handshake_message(conn, tls_context, server_hello);
        ParameterUtils.send_server_hello(server_hello, tls_context);
    }

    public static void send_certificate(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        Certificate cert = Certificate.getInstance();
        TLSUtils.send_handshake_message(conn, tls_context, cert);
    }

    public static void send_server_key_exchange(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        CipherSuiteIdentifier cipher_suite_id = tls_context.pending_send_parameters.suite;
        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;

        ServerKeyExchange server_key_exchange = null;
        switch (key_exchange) {
            case DHE_RSA: {
                server_key_exchange = generate_server_key_exchange_dhe_rsa(tls_context);
                break;
            }
            default:
                break;
        }

        if (server_key_exchange != null) {
            TLSUtils.send_handshake_message(conn, tls_context, server_key_exchange);
        }
    }

    private static ServerKeyExchange generate_server_key_exchange_dhe_rsa(TLSServerParameters tls_context) throws IOException {
        ProtocolVersion protocol_version = tls_context.protocol_version;
        switch (protocol_version) {
            case TLSv1_0:
            case TLSv1_1:
                return generate_server_key_exchange_dhe_rsa_tlsv1_0(tls_context);
            case TLSv1_2:
                return generate_server_key_exchange_dhe_rsa_tlsv1_2(tls_context);
            default:
                throw new RuntimeException("Unsupported Protocol Version: " + protocol_version);
        }
    }

    private static ServerKeyExchange generate_server_key_exchange_dhe_rsa_tlsv1_0(TLSServerParameters tls_context) throws IOException {
        // p
        byte[] p_bytes = DHKeyExchange.dh2236_p_bytes;
        int p_length = p_bytes.length;
        byte[] p_length_bytes = ByteUtils.toBytes(p_length, 2);
        BigInteger p = BigUtils.toBigInteger(p_bytes);

        // g
        byte[] g_bytes = DHKeyExchange.dh2236_g_bytes;
        int g_length = g_bytes.length;
        byte[] g_length_bytes = ByteUtils.toBytes(g_length, 2);
        BigInteger g = BigUtils.toBigInteger(g_bytes);

        // secret
        byte[] secret_bytes = ByteUtils.toBytes(System.currentTimeMillis());
        BigInteger secret = BigUtils.toBigInteger(secret_bytes);

        // Ys
        BigInteger Ys = g.modPow(secret, p);
        byte[] Ys_bytes = BigUtils.toByteArray(Ys);
        int Ys_length = Ys_bytes.length;
        byte[] Ys_length_bytes = ByteUtils.toBytes(Ys_length, 2);

        tls_context.dh_key = new DHKeyExchange(secret, g, p, Ys, null);

        // hash: md5 and sha1
        byte[] p_total_bytes = ByteUtils.concatenate(p_length_bytes, p_bytes);
        byte[] g_total_bytes = ByteUtils.concatenate(g_length_bytes, g_bytes);
        byte[] pub_key_total_bytes = ByteUtils.concatenate(Ys_length_bytes, Ys_bytes);
        byte[] message = ByteUtils.concatenate(p_total_bytes, g_total_bytes, pub_key_total_bytes);
        byte[] input = ByteUtils.concatenate(tls_context.client_random, tls_context.server_random, message);

        byte[] md5_digest = MD5Utils.md5_hash(input);
        byte[] sha1_digest = SHA1Utils.sha1_hash(input);
        byte[] digest = ByteUtils.concatenate(md5_digest, sha1_digest);

        // signature
        RSAKey private_key = tls_context.private_key_info.rsa_private_key.toKey();
        byte[] signature_bytes = RSAUtils.rsa_encrypt(digest, private_key);
        int signature_length = signature_bytes.length;
        byte[] signature_length_bytes = ByteUtils.toBytes(signature_length, 2);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        bao.write(p_length_bytes);
        bao.write(p_bytes);
        bao.write(g_length_bytes);
        bao.write(g_bytes);
        bao.write(Ys_length_bytes);
        bao.write(Ys_bytes);
        bao.write(signature_length_bytes);
        bao.write(signature_bytes);

        byte[] data = bao.toByteArray();
        return new ServerKeyExchange(data);
    }

    private static ServerKeyExchange generate_server_key_exchange_dhe_rsa_tlsv1_2(TLSServerParameters tls_context) throws IOException {
        // p
        byte[] p_bytes = DHKeyExchange.dh2236_p_bytes;
        int p_length = p_bytes.length;
        byte[] p_length_bytes = ByteUtils.toBytes(p_length, 2);
        BigInteger p = BigUtils.toBigInteger(p_bytes);

        // g
        byte[] g_bytes = DHKeyExchange.dh2236_g_bytes;
        int g_length = g_bytes.length;
        byte[] g_length_bytes = ByteUtils.toBytes(g_length, 2);
        BigInteger g = BigUtils.toBigInteger(g_bytes);

        // secret
        byte[] secret_bytes = ByteUtils.toBytes(System.currentTimeMillis());
        BigInteger secret = BigUtils.toBigInteger(secret_bytes);

        // Ys
        BigInteger Ys = g.modPow(secret, p);
        byte[] Ys_bytes = BigUtils.toByteArray(Ys);
        int Ys_length = Ys_bytes.length;
        byte[] Ys_length_bytes = ByteUtils.toBytes(Ys_length, 2);

        tls_context.dh_key = new DHKeyExchange(secret, g, p, Ys, null);

        // hash and signature algorithm
        byte[] hash_and_signature_bytes = new byte[2];
        hash_and_signature_bytes[0] = (byte) HashAlgorithm.SHA256.value;
        hash_and_signature_bytes[1] = (byte) SignatureAlgorithm.RSA.value;

        // hash: sha256
        byte[] p_total_bytes = ByteUtils.concatenate(p_length_bytes, p_bytes);
        byte[] g_total_bytes = ByteUtils.concatenate(g_length_bytes, g_bytes);
        byte[] pub_key_total_bytes = ByteUtils.concatenate(Ys_length_bytes, Ys_bytes);
        byte[] message = ByteUtils.concatenate(p_total_bytes, g_total_bytes, pub_key_total_bytes);
        byte[] input = ByteUtils.concatenate(tls_context.client_random, tls_context.server_random, message);

        byte[] digest = SHA256Utils.sha256_hash(input);

        // asn1
        byte[] asn1_prefix = HexUtils.parse("30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20", HexFormat.FORMAT_FF_SPACE_FF);
        byte[] asn1_digest = ByteUtils.concatenate(asn1_prefix, digest);

        // signature
        RSAKey private_key = tls_context.private_key_info.rsa_private_key.toKey();
        byte[] signature_bytes = RSAUtils.rsa_encrypt(asn1_digest, private_key);
        int signature_length = signature_bytes.length;
        byte[] signature_length_bytes = ByteUtils.toBytes(signature_length, 2);

        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        bao.write(p_length_bytes);
        bao.write(p_bytes);
        bao.write(g_length_bytes);
        bao.write(g_bytes);
        bao.write(Ys_length_bytes);
        bao.write(Ys_bytes);
        bao.write(hash_and_signature_bytes);
        bao.write(signature_length_bytes);
        bao.write(signature_bytes);

        byte[] data = bao.toByteArray();
        return new ServerKeyExchange(data);
    }

    public static void send_server_hello_done(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        ServerHelloDone server_hello_done = new ServerHelloDone();
        TLSUtils.send_handshake_message(conn, tls_context, server_hello_done);
    }

    /**
     * Finally, send server change cipher spec/finished message
     */
    public static void send_change_cipher_spec(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        byte[] content = ChangeCipherSpec.getContent();
        TLSUtils.send_message(conn, tls_context.active_send_parameters, ContentType.CONTENT_CHANGE_CIPHER_SPEC, tls_context.protocol_version, content);

        ParameterUtils.activate_send_parameter(tls_context);
    }

    /**
     * This message will be encrypted using the newly negotiated keys
     */
    public static void send_finished(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        byte[] verify_data = SecretUtils.compute_verify_data(ConnectionEnd.SERVER, tls_context);
        Finished finished_handshake_message = new Finished(verify_data);
        TLSUtils.send_handshake_message(conn, tls_context, finished_handshake_message);
    }
    // endregion

    // region receive
    public static void receive_tls_msg(TLSConnection conn, TLSServerParameters tls_context) throws IOException {
        TLSRecord record = TLSUtils.receive_message(conn, tls_context.active_recv_parameters);
        ContentType content_type = record.content_type;
        byte[] content = record.content;

        switch (content_type) {
            case CONTENT_CHANGE_CIPHER_SPEC:
                recv_change_cipher_spec(tls_context);
                break;
            case CONTENT_ALERT:
                Alert alert = Alert.parse(content);
                recv_alert(alert);
                break;
            case CONTENT_HANDSHAKE:
                Handshake handshake = Handshake.parse(content);
                recv_handshake(handshake, tls_context);

                // NOTE: 要先对handshake进行处理，再进行Hash计算；否则，计算出的verify data会出现错误。
                ParameterUtils.update_digest(content, tls_context);
                break;
            default:
                throw new RuntimeException("content type is wrong: " + content_type);
        }
    }

    public static void recv_change_cipher_spec(TLSParameters tls_context) {
        ParameterUtils.activate_recv_parameter(tls_context);
    }

    public static void recv_alert(Alert alert) {
        String line = String.format("Alert - %s: %s", alert.level, alert.description);
        System.out.println(line);
        if (alert.level == AlertLevel.FATAL) {
            throw new RuntimeException("Fatal Alert");
        }
    }

    public static void recv_handshake(Handshake handshake, TLSServerParameters tls_context) {
        HandshakeType hand_shake_type = handshake.hand_shake_type;
        switch (hand_shake_type) {
            case CLIENT_HELLO:
                ClientHello client_hello = (ClientHello) handshake;
                recv_client_hello(client_hello, tls_context);
                break;
            case CLIENT_KEY_EXCHANGE:
                ClientKeyExchange client_key_exchange = (ClientKeyExchange) handshake;
                recv_client_key_exchange(client_key_exchange, tls_context);
                break;
            case FINISHED:
                Finished finished = (Finished) handshake;
                recv_finished(finished, tls_context);
                break;
            default:
                throw new RuntimeException("hand shake type is wrong: " + hand_shake_type);
        }
    }

    public static void recv_client_hello(ClientHello client_hello, TLSServerParameters tls_context) {
        ParameterUtils.recv_client_hello(client_hello, tls_context);
    }

    public static void recv_client_key_exchange(ClientKeyExchange client_key_exchange, TLSServerParameters tls_context) {
        ProtectionParameters pending_recv_parameters = tls_context.pending_recv_parameters;
        CipherSuiteIdentifier cipher_suite_id = pending_recv_parameters.suite;
        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;
        byte[] pre_master_key;
        switch (key_exchange) {
            case RSA: {
                pre_master_key = KeyExchangeUtils.decrypt_rsa_key_exchange(client_key_exchange.data, tls_context.private_key_info.rsa_private_key.toKey());
                break;
            }
            case DHE_RSA: {
                pre_master_key = recv_client_key_exchange_dhe_rsa_tlsv1(client_key_exchange, tls_context);
                break;
            }
            default:
                throw new RuntimeException("Server Key Exchange Not supported: " + key_exchange);
        }

        tls_context.pre_master_secret = pre_master_key;
        SecretUtils.compute_master_secret(tls_context);

        // TODO: - for security, should also “purge” the pre-master secret from memory.
        SecretUtils.calculate_keys(tls_context);
    }

    public static byte[] recv_client_key_exchange_dhe_rsa_tlsv1(ClientKeyExchange client_key_exchange, TLSParameters tls_context) {
        byte[] data = client_key_exchange.data;
        ByteDashboard bd = new ByteDashboard(data);

        // Yc
        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        byte[] Yc_bytes = bd.nextN(pub_key_length);
        BigInteger Yc = BigUtils.toBigInteger(Yc_bytes);

        // Z
        BigInteger p = tls_context.dh_key.p;
        BigInteger secret = tls_context.dh_key.secret;
        BigInteger Z = Yc.modPow(secret, p);

        int pre_master_secret_len = BigUtils.toByteSize(tls_context.dh_key.p);
        byte[] pre_master_secret = new byte[pre_master_secret_len];
        byte[] Z_bytes = BigUtils.toByteArray(Z);
        System.arraycopy(Z_bytes, 0, pre_master_secret, pre_master_secret.length - Z_bytes.length, Z_bytes.length);
        return pre_master_secret;
    }

    public static void recv_finished(Finished finished, TLSParameters tls_context) {
        byte[] data = finished.data;
        byte[] verify_data = SecretUtils.compute_verify_data(ConnectionEnd.CLIENT, tls_context);
        if (!Arrays.equals(data, verify_data)) {
            System.out.println("Expected Verify Data: " + HexUtils.format(verify_data, HexFormat.FORMAT_FF_SPACE_FF));
            System.out.println("Received Verify Data: " + HexUtils.format(data, HexFormat.FORMAT_FF_SPACE_FF));
            throw new RuntimeException("verify data is not right");
        }

        ParameterUtils.recv_finished(tls_context);
    }
    // endregion

}
