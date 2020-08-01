package lsieun.tls.utils;

import lsieun.crypto.hash.updateable.Digest;
import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.tls.cipher.CipherSuite;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.handshake.ClientHello;
import lsieun.tls.cipher.ConnectionEnd;
import lsieun.tls.param.ProtectionParameters;
import lsieun.tls.param.TLSParameters;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.nio.charset.StandardCharsets;

public class SecretUtils {
    public static CipherSuiteIdentifier select_cipher_suite(ClientHello client_hello) {
        // FIXME: 这里应该根据Client提供的cipher里面进行选择

        return CipherSuiteIdentifier.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }

    public static byte[] generate_pre_master_secret(ProtocolVersion protocol_version) {
        byte[] pre_master_secret = new byte[TLSConst.MASTER_SECRET_LENGTH];
        pre_master_secret[0] = (byte) protocol_version.major;
        pre_master_secret[1] = (byte) protocol_version.minor;
        for (int i = 2; i < TLSConst.MASTER_SECRET_LENGTH; i++) {
            // TODO: SHOULD BE RANDOM!
            pre_master_secret[i] = (byte) i;
        }
        return pre_master_secret;
    }

    public static void compute_master_secret(TLSParameters tls_context) {
        tls_context.master_secret = calculate_master_secret(tls_context.protocol_version, tls_context.pre_master_secret, tls_context.client_random, tls_context.server_random);
    }

    /**
     * master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random );
     * always 48 bytes in length.
     */
    public static byte[] calculate_master_secret(ProtocolVersion protocol_version, byte[] pre_master_secret, byte[] client_random, byte[] server_random) {
        byte[] label = "master secret".getBytes(StandardCharsets.UTF_8);
        byte[] seed = ByteUtils.concatenate(client_random, server_random);
        return PRFUtils.PRF(protocol_version, pre_master_secret, label, seed, TLSConst.MASTER_SECRET_LENGTH);
    }

    public static void calculate_keys(TLSParameters tls_context) {
        // NOTE: assuming send suite & recv suite will always be the same
        CipherSuite suite = CipherSuite.valueOf(tls_context.pending_send_parameters.suite);
        int hash_size = suite.mac_algorithm.hash_size;
        int key_size = suite.bulk_cipher_algorithm.key_size;
        int iv_size = suite.bulk_cipher_algorithm.block_size;

        int key_block_length = hash_size * 2 + key_size * 2 + iv_size * 2;

        byte[] key_block = calculate_keys(tls_context.protocol_version, key_block_length, tls_context.master_secret, tls_context.client_random, tls_context.server_random);

        ByteDashboard bd = new ByteDashboard(key_block);

        ProtectionParameters send_parameters = tls_context.pending_send_parameters;
        ProtectionParameters recv_parameters = tls_context.pending_recv_parameters;

        ConnectionEnd connection_end = tls_context.connection_end;
        switch (connection_end) {
            case CLIENT:
                send_parameters.mac_secret = bd.nextN(hash_size);
                recv_parameters.mac_secret = bd.nextN(hash_size);
                send_parameters.key = bd.nextN(key_size);
                recv_parameters.key = bd.nextN(key_size);
                send_parameters.iv = bd.nextN(iv_size);
                recv_parameters.iv = bd.nextN(iv_size);
                break;
            case SERVER:
                recv_parameters.mac_secret = bd.nextN(hash_size);
                send_parameters.mac_secret = bd.nextN(hash_size);
                recv_parameters.key = bd.nextN(key_size);
                send_parameters.key = bd.nextN(key_size);
                recv_parameters.iv = bd.nextN(iv_size);
                send_parameters.iv = bd.nextN(iv_size);
                break;
            default:
                throw new RuntimeException("Unknown connection end: " + connection_end);
        }
    }

    public static byte[] calculate_keys(ProtocolVersion protocol_version, int key_length, byte[] master_secret, byte[] client_random, byte[] server_random) {
        byte[] label = "key expansion".getBytes(StandardCharsets.UTF_8);
        byte[] seed = ByteUtils.concatenate(server_random, client_random);
        return PRFUtils.PRF(protocol_version, master_secret, label, seed, key_length);
    }

    public static byte[] compute_verify_data(ConnectionEnd connection_end, TLSParameters tls_context) {
        return compute_verify_data(connection_end,
                tls_context.protocol_version,
                tls_context.master_secret,
                tls_context.md5_handshake_digest,
                tls_context.sha1_handshake_digest,
                tls_context.sha256_handshake_digest);
    }

    /**
     * verify_data = PRF(master_secret, "client finished", MD5(handshake_messages) + SHA-1(handshake_messages));
     * verify_data = PRF(master_secret, "server finished", MD5(handshake_messages) + SHA-1(handshake_messages));
     *
     */
    public static byte[] compute_verify_data(ConnectionEnd connection_end,
                                             ProtocolVersion protocol_version,
                                             byte[] master_secret,
                                             DigestCtx md5_handshake_digest,
                                             DigestCtx sha1_handshake_digest,
                                             DigestCtx sha256_handshake_digest) {
        String finished_label = (connection_end == ConnectionEnd.CLIENT) ? "client finished" : "server finished";
        byte[] finished_label_bytes = finished_label.getBytes(StandardCharsets.UTF_8);

        byte[] handshake_hash;
        switch (protocol_version) {
            case TLSv1_0:
            case TLSv1_1:
                byte[] md5_digest = Digest.finalize_digest(md5_handshake_digest);
                byte[] sha1_digest = Digest.finalize_digest(sha1_handshake_digest);
                handshake_hash = ByteUtils.concatenate(md5_digest, sha1_digest);
                break;
            case TLSv1_2:
                handshake_hash = Digest.finalize_digest(sha256_handshake_digest);
                break;
            default:
                throw new RuntimeException("Unsupported TLS Version: " + protocol_version);
        }

        return PRFUtils.PRF(protocol_version, master_secret, finished_label_bytes, handshake_hash, TLSConst.VERIFY_DATA_LEN);
    }

}
