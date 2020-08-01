package lsieun.tls.utils;

import lsieun.crypto.hash.updateable.Digest;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.handshake.Certificate;
import lsieun.tls.entity.handshake.ClientHello;
import lsieun.tls.entity.handshake.ServerHello;
import lsieun.tls.param.ProtectionParameters;
import lsieun.tls.param.TLSClientParameters;
import lsieun.tls.param.TLSParameters;
import lsieun.tls.param.TLSServerParameters;

public class ParameterUtils {
    public static void send_client_hello(ClientHello client_hello, TLSParameters tls_context) {
        byte[] client_random = client_hello.random.toBytes();
        tls_context.protocol_version = client_hello.client_version;
        tls_context.client_random = client_random;
    }

    public static void recv_client_hello(ClientHello client_hello, TLSServerParameters tls_context) {
        // (1) client random
        byte[] client_random = client_hello.random.toBytes();
        tls_context.protocol_version = client_hello.client_version;
        tls_context.client_random = client_random;

        // (2) session id
        if (client_hello.session_id.length > 0) {
            TLSSessionStore.find_stored_session(client_hello.session_id, tls_context);
        }

        // (3) cipher suite
        CipherSuiteIdentifier cipher_suite_id = SecretUtils.select_cipher_suite(client_hello);
        tls_context.pending_recv_parameters.suite = cipher_suite_id;
        tls_context.pending_send_parameters.suite = cipher_suite_id;

        // (4) change flag
        tls_context.got_client_hello = true;
    }

    public static void send_server_hello(ServerHello server_hello, TLSParameters tls_context) {
        byte[] server_random = server_hello.random.toBytes();
        tls_context.server_random = server_random;
        tls_context.session_id = server_hello.session_id;
    }

    public static void recv_server_hello(ServerHello server_hello, TLSParameters tls_context) {
        byte[] server_random = server_hello.random.toBytes();
        tls_context.server_random = server_random;
        tls_context.session_id = server_hello.session_id;

        CipherSuiteIdentifier cipher_suite_id = server_hello.cipher_suite_id;
        tls_context.pending_recv_parameters.suite = cipher_suite_id;
        tls_context.pending_send_parameters.suite = cipher_suite_id;
    }

    public static void recv_certificate(Certificate certificate, TLSClientParameters tls_context) {
        tls_context.server_public_key = certificate.cert_list.get(0).tbs_certificate.subjectPublicKeyInfo;
    }

    public static void recv_server_hello_done(TLSClientParameters tls_context) {
        tls_context.server_hello_done = true;
    }

    public static void recv_finished(TLSParameters tls_context) {
        tls_context.peer_finished = true;
    }

    public static void activate_send_parameter(TLSParameters tls_context) {
        tls_context.pending_send_parameters.seq_num = 0;
        tls_context.active_send_parameters = tls_context.pending_send_parameters;
        tls_context.pending_send_parameters = new ProtectionParameters();
    }

    public static void activate_recv_parameter(TLSParameters tls_context) {
        tls_context.pending_recv_parameters.seq_num = 0;
        tls_context.active_recv_parameters = tls_context.pending_recv_parameters;
        tls_context.pending_recv_parameters = new ProtectionParameters();
    }

    public static void update_digest(byte[] handshake_bytes, TLSParameters tls_context) {
        ProtocolVersion protocol_version = tls_context.protocol_version;
        switch (protocol_version) {
            case TLSv1_0:
            case TLSv1_1:
                Digest.update_digest(tls_context.md5_handshake_digest, handshake_bytes);
                Digest.update_digest(tls_context.sha1_handshake_digest, handshake_bytes);
                break;
            case TLSv1_2:
                Digest.update_digest(tls_context.sha256_handshake_digest, handshake_bytes);
                break;
            default:
                throw new RuntimeException("Unsupported TLS Version: " + protocol_version);
        }
    }

}
