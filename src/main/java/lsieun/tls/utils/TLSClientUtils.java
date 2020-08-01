package lsieun.tls.utils;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
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
import lsieun.tls.param.TLSClientParameters;
import lsieun.tls.param.TLSParameters;
import lsieun.utils.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class TLSClientUtils {
    /**
     * Negotiate an TLS channel on an already-established socket.
     */
    public static void tls_connect(TLSConnection conn, TLSClientParameters tls_context) throws IOException {
        tls_context.connection_end = ConnectionEnd.CLIENT;

        // Step 1. Send the TLS handshake “client hello” message
        send_client_hello(conn, tls_context, null);

        // Step 2. Receive the server response
        while (!tls_context.server_hello_done) {
            receive_tls_msg(conn, tls_context);
        }

        // Step 3. Send client key exchange, change cipher spec and encrypted handshake message
        send_client_key_exchange(conn, tls_context);

        send_change_cipher_spec(conn, tls_context);

        // This message will be encrypted using the newly negotiated keys
        send_finished(conn, tls_context);

        while (!tls_context.peer_finished) {
            receive_tls_msg(conn, tls_context);
        }
    }

    public static void tls_resume(TLSConnection conn, byte[] session_id, byte[] master_secret, TLSClientParameters tls_context) throws IOException {
        tls_context.connection_end = ConnectionEnd.CLIENT;
        tls_context.session_id = session_id;

        send_client_hello(conn, tls_context, session_id);

        while (!tls_context.peer_finished) {
            receive_tls_msg(conn, tls_context);
            if (tls_context.server_hello_done) {
                if (Arrays.equals(session_id, tls_context.session_id)) {
                    System.out.println("Server refused to renegotiate, exiting.");
                    System.exit(0);
                }
            }
            else {
                tls_context.master_secret = master_secret;
                SecretUtils.calculate_keys(tls_context);
            }
        }


        send_change_cipher_spec(conn, tls_context);

        send_finished(conn, tls_context);
    }

    // region send
    public static void send_client_hello(TLSConnection conn, TLSParameters tls_context, byte[] session_id) throws IOException {
        ClientHello client_hello;
        if (session_id != null) {
            client_hello = ClientHello.getInstance(session_id);
        }
        else {
            client_hello = ClientHello.getInstance();
        }

        ParameterUtils.send_client_hello(client_hello, tls_context);
        TLSUtils.send_handshake_message(conn, tls_context, client_hello);
    }

    public static void send_client_key_exchange(TLSConnection conn, TLSParameters tls_context) throws IOException {
        byte[] pre_master_secret;
        byte[] key_exchange_message;

        CipherSuiteIdentifier cipher_suite_id = tls_context.pending_send_parameters.suite;
        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;

        switch (key_exchange) {
            case NULL: {
                pre_master_secret = SecretUtils.generate_pre_master_secret(tls_context.protocol_version);
                int pre_master_secret_length = pre_master_secret.length;

                key_exchange_message = new byte[pre_master_secret_length + 2];
                key_exchange_message[0] = (byte) (pre_master_secret_length >> 8 & 0xFF);
                key_exchange_message[1] = (byte) (pre_master_secret_length & 0xFF);
                System.arraycopy(pre_master_secret, 0, key_exchange_message, 2, pre_master_secret_length);
                break;
            }
            case RSA: {
                pre_master_secret = SecretUtils.generate_pre_master_secret(tls_context.protocol_version);

                RSAKey public_key = tls_context.server_public_key.rsa_public_key.toKey();
                byte[] encrypted_pre_master_key = RSAUtils.rsa_encrypt(pre_master_secret, public_key);
                int encrypted_length = encrypted_pre_master_key.length;

                key_exchange_message = new byte[encrypted_length + 2];
                key_exchange_message[0] = (byte) (encrypted_length >> 8 & 0xFF);
                key_exchange_message[1] = (byte) (encrypted_length & 0xFF);
                System.arraycopy(encrypted_pre_master_key, 0, key_exchange_message, 2, encrypted_length);
                break;
            }
            case DHE_RSA: {
                int pre_master_secret_len = BigUtils.toByteSize(tls_context.dh_key.p);
                pre_master_secret = new byte[pre_master_secret_len];

                BigInteger g = tls_context.dh_key.g;
                BigInteger p = tls_context.dh_key.p;
                BigInteger Ys = tls_context.dh_key.Ys;

                // TODO: obviously, make this random, and much longer
                BigInteger secret = new BigInteger("6");
                BigInteger Yc = g.modPow(secret, p);
                BigInteger Z = Ys.modPow(secret, p);

                byte[] Z_bytes = BigUtils.toByteArray(Z);
                System.arraycopy(Z_bytes, 0, pre_master_secret, pre_master_secret.length - Z_bytes.length, Z_bytes.length);

                byte[] Yc_bytes = BigUtils.toByteArray(Yc);
                int Yc_length = Yc_bytes.length;
                int message_size = Yc_bytes.length + 2;

                key_exchange_message = new byte[message_size];
                key_exchange_message[0] = (byte) ((Yc_length >> 8) & 0xFF);
                key_exchange_message[1] = (byte) (Yc_length & 0xFF);
                System.arraycopy(Yc_bytes, 0, key_exchange_message, 2, Yc_bytes.length);
                break;
            }
            default:
                throw new RuntimeException("Unsupported Key Exchange: " + key_exchange);
        }

//        switch (cipher_suite_id) {
//            case TLS_NULL_WITH_NULL_NULL:
//                // TODO: 有没有server支持这个呢？
//                // TODO: this is an error, exit here
//                throw new RuntimeException("TLS_NULL_WITH_NULL_NULL Not Support");
//            case TLS_RSA_WITH_NULL_MD5:
//            case TLS_RSA_WITH_NULL_SHA:
//            case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
//            case TLS_RSA_WITH_RC4_128_MD5:
//            case TLS_RSA_WITH_RC4_128_SHA:
//            case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
//            case TLS_RSA_WITH_IDEA_CBC_SHA:
//            case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
//            case TLS_RSA_WITH_DES_CBC_SHA:
//            case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
//            case TLS_RSA_WITH_AES_128_CBC_SHA:
//                pre_master_secret = new byte[TLSConst.MASTER_SECRET_LENGTH];
//                key_exchange_message = KeyExchangeUtils.rsa_key_exchange(tls_context.server_public_key.rsa_public_key.toKey(), pre_master_secret);
//                break;
//            case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
//            case TLS_DH_DSS_WITH_DES_CBC_SHA:
//            case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
//            case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
//            case TLS_DH_RSA_WITH_DES_CBC_SHA:
//            case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
//                int pre_master_secret_len = BigUtils.toByteSize(tls_context.server_dh_key.p);
//                pre_master_secret = new byte[pre_master_secret_len];
//                key_exchange_message = KeyExchangeUtils.dh_key_exchange(tls_context.server_dh_key, pre_master_secret);
//                break;
//            default:
//                throw new RuntimeException("Unsupported Cipher Suite " + cipher_suite_id);
//        }

        ClientKeyExchange client_key_exchange = new ClientKeyExchange(key_exchange_message);
        TLSUtils.send_handshake_message(conn, tls_context, client_key_exchange);

        // Now, turn the pre-master secret into an actual master secret (the
        // server side will do this concurrently).
        tls_context.pre_master_secret = pre_master_secret;
        SecretUtils.compute_master_secret(tls_context);

        // TODO: - for security, should also “purge” the pre-master secret from memory.
        SecretUtils.calculate_keys(tls_context);
    }

    public static void send_change_cipher_spec(TLSConnection conn, TLSParameters tls_context) throws IOException {
        byte[] content = ChangeCipherSpec.getContent();
        TLSUtils.send_message(conn, tls_context.active_send_parameters, ContentType.CONTENT_CHANGE_CIPHER_SPEC, tls_context.protocol_version, content);

        ParameterUtils.activate_send_parameter(tls_context);
    }

    public static void send_finished(TLSConnection conn, TLSParameters tls_context) throws IOException {
        byte[] verify_data = SecretUtils.compute_verify_data(ConnectionEnd.CLIENT, tls_context);
        Finished finished_handshake_message = new Finished(verify_data);
        TLSUtils.send_handshake_message(conn, tls_context, finished_handshake_message);
    }
    // endregion

    // region receive
    public static void receive_tls_msg(TLSConnection conn, TLSClientParameters tls_context) throws IOException {
        TLSRecord tls_record = TLSUtils.receive_message(conn, tls_context.active_recv_parameters);

        ContentType content_type = tls_record.content_type;
        byte[] content = tls_record.content;

        switch (content_type) {
            case CONTENT_CHANGE_CIPHER_SPEC:
                recv_change_cipher_spec(tls_context);
                break;
            case CONTENT_ALERT:
                Alert alert = Alert.parse(content);
                recv_alert(alert);
                break;
            case CONTENT_HANDSHAKE:
                // single
//                Handshake handshake = Handshake.parse(content);
//                recv_handshake(handshake, tls_context);

                // multi
                recv_handshake(content, tls_context);

                // NOTE: 要先对handshake进行处理，再进行Hash计算；否则，计算出的verify data会出现错误。
                ParameterUtils.update_digest(content, tls_context);
                break;
            case CONTENT_APPLICATION_DATA:
                break;
            default:
                throw new RuntimeException("Unknown Content Type: " + content_type);
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

    public static void recv_handshake(byte[] content, TLSClientParameters tls_context) {
        List<Handshake> handshake_list = Handshake.parse_list(content);
        for (Handshake item : handshake_list) {
            recv_handshake(item, tls_context);
        }
    }

    public static void recv_handshake(Handshake handshake, TLSClientParameters tls_context) {
        HandshakeType hand_shake_type = handshake.hand_shake_type;
        switch (hand_shake_type) {
            case SERVER_HELLO:
                ServerHello server_hello = (ServerHello) handshake;
                recv_server_hello(server_hello, tls_context);
                break;
            case CERTIFICATE:
                Certificate certificate = (Certificate) handshake;
                recv_certificate(certificate, tls_context);
                break;
            case SERVER_KEY_EXCHANGE:
                ServerKeyExchange server_key_exchange = (ServerKeyExchange) handshake;
                recv_server_key_exchange(server_key_exchange, tls_context);
                break;
            case SERVER_HELLO_DONE:
                recv_server_hello_done(tls_context);
                break;
            case FINISHED:
                Finished finished = (Finished) handshake;
                recv_finished(finished, tls_context);
                break;
            default:
                throw new RuntimeException("Unknown hand shake type: " + hand_shake_type);
        }
    }

    public static void recv_server_hello(ServerHello server_hello, TLSClientParameters tls_context) {
        ParameterUtils.recv_server_hello(server_hello, tls_context);
    }

    // TODO: The most important certificate is the first one, since this contains the public key of the subject
    // TODO: Each subsequent certificate acts as a signer for the previous certificate.
    // TODO: 1，下一个证书public key要验证上一个证书的Signature
    // TODO：2, 除了第1个证书，其它必须是CA证书
    public static void recv_certificate(Certificate certificate, TLSClientParameters tls_context) {
        ParameterUtils.recv_certificate(certificate, tls_context);
    }


    public static void recv_server_key_exchange(ServerKeyExchange server_key_exchange, TLSParameters tls_context) {
        ProtectionParameters pending_recv_parameters = tls_context.pending_recv_parameters;
        CipherSuiteIdentifier cipher_suite_id = pending_recv_parameters.suite;
        CipherSuite cipher_suite = CipherSuite.valueOf(cipher_suite_id);
        KeyExchange key_exchange = cipher_suite.key_exchange;
        switch (key_exchange) {
            case DHE_RSA: {
                parse_server_key_exchange_dhe_rsa(server_key_exchange, tls_context);
                break;
            }
            default:
                throw new RuntimeException("Server Key Exchange Not supported: " + key_exchange);
        }
    }

    public static void parse_server_key_exchange_dhe_rsa(ServerKeyExchange server_key_exchange, TLSParameters tls_context) {
        ProtocolVersion protocol_version = tls_context.protocol_version;
        switch (protocol_version) {
            case TLSv1_0:
            case TLSv1_1:
                parse_server_key_exchange_dhe_rsa_tlsv1_0(server_key_exchange, tls_context);
                break;
            case TLSv1_2:
                parse_server_key_exchange_dhe_rsa_tlsv1_2(server_key_exchange, tls_context);
                break;
            default:
                throw new RuntimeException("Unsupported Protocol Version: " + protocol_version);
        }
    }

    public static void parse_server_key_exchange_dhe_rsa_tlsv1_0(ServerKeyExchange server_key_exchange, TLSParameters tls_context) {
        byte[] data = server_key_exchange.data;
        ByteDashboard bd = new ByteDashboard(data);

        // p
        byte[] p_length_bytes = bd.nextN(2);
        int p_length = ByteUtils.toInt(p_length_bytes);
        byte[] p_bytes = bd.nextN(p_length);
        BigInteger p = BigUtils.toBigInteger(p_bytes);

        // g
        byte[] g_length_bytes = bd.nextN(2);
        int g_length = ByteUtils.toInt(g_length_bytes);
        byte[] g_bytes = bd.nextN(g_length);
        BigInteger g = BigUtils.toBigInteger(g_bytes);

        // pub key
        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        byte[] pub_key_bytes = bd.nextN(pub_key_length);
        BigInteger Ys = BigUtils.toBigInteger(pub_key_bytes);

        tls_context.dh_key = new DHKeyExchange(null, g, p, Ys, null);

        // hash: md5 and sha1
        byte[] p_total_bytes = ByteUtils.concatenate(p_length_bytes, p_bytes);
        byte[] g_total_bytes = ByteUtils.concatenate(g_length_bytes, g_bytes);
        byte[] pub_key_total_bytes = ByteUtils.concatenate(pub_key_length_bytes, pub_key_bytes);
        byte[] message = ByteUtils.concatenate(p_total_bytes, g_total_bytes, pub_key_total_bytes);
        byte[] input = ByteUtils.concatenate(tls_context.client_random, tls_context.server_random, message);

        byte[] md5_digest = MD5Utils.md5_hash(input);
        byte[] sha1_digest = SHA1Utils.sha1_hash(input);
        byte[] digest = ByteUtils.concatenate(md5_digest, sha1_digest);

        // verify signature
        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        byte[] signature_bytes = bd.nextN(signature_length);

        RSAKey pub_key = tls_context.server_public_key.rsa_public_key.toKey();
        byte[] decrypted_bytes = RSAUtils.rsa_decrypt(signature_bytes, pub_key);
        boolean flag = Arrays.equals(digest, decrypted_bytes);
        if (!flag) {
            throw new RuntimeException("Server Key Exchange Signature is Not right.");
        }
    }

    public static void parse_server_key_exchange_dhe_rsa_tlsv1_2(ServerKeyExchange server_key_exchange, TLSParameters tls_context) {
        byte[] data = server_key_exchange.data;
        ByteDashboard bd = new ByteDashboard(data);

        // p
        byte[] p_length_bytes = bd.nextN(2);
        int p_length = ByteUtils.toInt(p_length_bytes);
        byte[] p_bytes = bd.nextN(p_length);
        BigInteger p = BigUtils.toBigInteger(p_bytes);

        // g
        byte[] g_length_bytes = bd.nextN(2);
        int g_length = ByteUtils.toInt(g_length_bytes);
        byte[] g_bytes = bd.nextN(g_length);
        BigInteger g = BigUtils.toBigInteger(g_bytes);

        // pub key
        byte[] pub_key_length_bytes = bd.nextN(2);
        int pub_key_length = ByteUtils.toInt(pub_key_length_bytes);
        byte[] pub_key_bytes = bd.nextN(pub_key_length);
        BigInteger Ys = BigUtils.toBigInteger(pub_key_bytes);

        tls_context.dh_key = new DHKeyExchange(null, g, p, Ys, null);

        byte[] hash_and_signature_bytes = bd.nextN(2);
        byte hash_algorithm_val = hash_and_signature_bytes[0];
        byte signature_algorithm_val = hash_and_signature_bytes[1];
        HashAlgorithm hash_algorithm = HashAlgorithm.valueOf(hash_algorithm_val);
        SignatureAlgorithm signature_algorithm = SignatureAlgorithm.valueOf(signature_algorithm_val);
        if (signature_algorithm != SignatureAlgorithm.RSA) {
            throw new RuntimeException("Server Key Exchange: " + hash_algorithm + ", " + signature_algorithm);
        }

        // hash: sha256
        byte[] p_total_bytes = ByteUtils.concatenate(p_length_bytes, p_bytes);
        byte[] g_total_bytes = ByteUtils.concatenate(g_length_bytes, g_bytes);
        byte[] pub_key_total_bytes = ByteUtils.concatenate(pub_key_length_bytes, pub_key_bytes);
        byte[] message = ByteUtils.concatenate(p_total_bytes, g_total_bytes, pub_key_total_bytes);
        byte[] input = ByteUtils.concatenate(tls_context.client_random, tls_context.server_random, message);

        byte[] digest;
        switch (hash_algorithm) {
            case MD5:
                digest = MD5Utils.md5_hash(input);
                break;
            case SHA1:
                digest = SHA1Utils.sha1_hash(input);
                break;
            case SHA256:
                 digest = SHA256Utils.sha256_hash(input);
                 break;
            default:
                throw new RuntimeException("Unsupported Hash Algorithm: " + hash_algorithm);
        }

        // verify signature
        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        byte[] signature_bytes = bd.nextN(signature_length);

        RSAKey pub_key = tls_context.server_public_key.rsa_public_key.toKey();
        byte[] decrypted_bytes = RSAUtils.rsa_decrypt(signature_bytes, pub_key);
        ASN1Struct asn1_seq = ASN1Utils.parse_der(decrypted_bytes).get(0);
        ASN1Struct asn1_oid = asn1_seq.children.get(0);
        ASN1Struct asn1_signature = asn1_seq.children.get(1);

//        ObjectIdentifier oid = ObjectIdentifier.valueOf(asn1_oid.children.get(0).data);
//        if (oid != ObjectIdentifier.SHA256) {
//            throw new RuntimeException("Unsupported Object Identifier: " + oid);
//        }

        byte[] received_digest = asn1_signature.data;
        boolean flag = Arrays.equals(digest, received_digest);
        if (!flag) {
            System.out.println("Calculated Digest: " + HexUtils.format(digest, HexFormat.FORMAT_FF_SPACE_FF));
            System.out.println("Received   Digest: " + HexUtils.format(received_digest, HexFormat.FORMAT_FF_SPACE_FF));
            throw new RuntimeException("Server Key Exchange Signature is Not right.");
        }
    }

    public static void recv_server_hello_done(TLSClientParameters tls_context) {
        ParameterUtils.recv_server_hello_done(tls_context);
    }

    public static void recv_finished(Finished finished, TLSParameters tls_context) {
        byte[] data = finished.data;
        byte[] verify_data = SecretUtils.compute_verify_data(ConnectionEnd.SERVER, tls_context);
        if (!Arrays.equals(data, verify_data)) {
            System.out.println("Expected Verify Data: " + HexUtils.format(verify_data, HexFormat.FORMAT_FF_SPACE_FF));
            System.out.println("Received Verify Data: " + HexUtils.format(data, HexFormat.FORMAT_FF_SPACE_FF));
            throw new RuntimeException("verify data is not right");
        }
        ParameterUtils.recv_finished(tls_context);
    }
    // endregion

}
