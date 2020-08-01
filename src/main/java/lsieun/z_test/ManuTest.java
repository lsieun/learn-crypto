package lsieun.z_test;

import lsieun.crypto.hash.updateable.Digest;
import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.tls.cipher.CipherSuite;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.handshake.ClientHello;
import lsieun.tls.entity.handshake.Finished;
import lsieun.tls.entity.handshake.Handshake;
import lsieun.tls.entity.handshake.ServerHello;
import lsieun.tls.utils.*;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;
import lsieun.utils.SSLLog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ManuTest {

    public static final String filename = "log/baidu_tlsv1.txt";

    public static void main(String[] args) throws IOException {
        DigestCtx md5_handshake_digest = DigestCtx.new_md5_digest();
        DigestCtx sha1_handshake_digest = DigestCtx.new_sha1_digest();

        // client hello
        byte[] client_hello_record_bytes = SSLLog.read_data(filename, "33-38");
        TLSRecord client_hello_record = TLSRecord.parse(client_hello_record_bytes);
        DisplayUtils.display_record(client_hello_record_bytes);
        byte[] client_hello_handshake_bytes = client_hello_record.content;
        ClientHello client_hello = (ClientHello) Handshake.parse(client_hello_handshake_bytes);
        ProtocolVersion protocol_version = client_hello.client_version;
        byte[] client_random_bytes = client_hello.random.toBytes();

        Digest.update_digest(md5_handshake_digest, client_hello_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, client_hello_handshake_bytes);

        // server hello
        byte[] server_hello_record_bytes = SSLLog.read_data(filename, "40-40,42-46");
        TLSRecord server_hello_record = TLSRecord.parse(server_hello_record_bytes);
        DisplayUtils.display_record(server_hello_record_bytes);
        byte[] server_hello_handshake_bytes = server_hello_record.content;
        ServerHello server_hello = (ServerHello) Handshake.parse(server_hello_handshake_bytes);
        byte[] server_random_bytes = server_hello.random.toBytes();

        Digest.update_digest(md5_handshake_digest, server_hello_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, server_hello_handshake_bytes);

        // server certificate
        byte[] certificate_record_bytes = SSLLog.read_data(filename, "76-76,78-312");
        TLSRecord certificate_record = TLSRecord.parse(certificate_record_bytes);
        DisplayUtils.display_record(certificate_record_bytes);
        byte[] certificate_handshake_bytes = certificate_record.content;

        Digest.update_digest(md5_handshake_digest, certificate_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, certificate_handshake_bytes);

        // server hello done
        byte[] server_hello_done_bytes = SSLLog.read_data(filename, "896-896,898-898");
        TLSRecord server_hello_done_record = TLSRecord.parse(server_hello_done_bytes);
        DisplayUtils.display_record(server_hello_done_bytes);
        byte[] server_hello_done_handshake_bytes = server_hello_done_record.content;

        Digest.update_digest(md5_handshake_digest, server_hello_done_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, server_hello_done_handshake_bytes);

        // client key exchange
        byte[] client_key_exchange_bytes = SSLLog.read_data(filename, "939-955");
        TLSRecord client_key_exchange_record = TLSRecord.parse(client_key_exchange_bytes);
        DisplayUtils.display_record(client_key_exchange_bytes);
        byte[] client_key_exchange_handshake_bytes = client_key_exchange_record.content;

        Digest.update_digest(md5_handshake_digest, client_key_exchange_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, client_key_exchange_handshake_bytes);

        // PreMaster Secret
        byte[] pre_master_secret_bytes = SSLLog.read_data(filename, "958-960");
        byte[] master_secret_bytes = SecretUtils.calculate_master_secret(protocol_version, pre_master_secret_bytes, client_random_bytes, server_random_bytes);

        CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.TLS_RSA_WITH_AES_128_CBC_SHA;
        CipherSuite suite = CipherSuite.valueOf(cipher_suite_id);
        int hash_size = suite.mac_algorithm.hash_size;
        int key_size = suite.bulk_cipher_algorithm.key_size;
        int iv_size = suite.bulk_cipher_algorithm.block_size;
        int key_block_length = hash_size * 2 + key_size * 2 + iv_size * 2;
        byte[] label = "key expansion".getBytes(StandardCharsets.UTF_8);
        byte[] seed = ByteUtils.concatenate(server_random_bytes, client_random_bytes);
        byte[] key_block = PRFUtils.PRF(protocol_version, master_secret_bytes, label, seed, key_block_length);

        ByteDashboard bd = new ByteDashboard(key_block);
        byte[] send_mac_secret = bd.nextN(hash_size);
        byte[] recv_mac_secret = bd.nextN(hash_size);
        byte[] send_key = bd.nextN(key_size);
        byte[] recv_key = bd.nextN(key_size);
        byte[] send_iv = bd.nextN(iv_size);
        byte[] recv_iv = bd.nextN(iv_size);

        // client change cipher spec
        byte[] client_change_cipher_spec_bytes = SSLLog.read_data(filename, "992-992");
        TLSRecord client_change_cipher_spec_record = TLSRecord.parse(client_change_cipher_spec_bytes);
        DisplayUtils.display_record(client_change_cipher_spec_bytes);

        // client finish verify data
        byte[] finished_label = "client finished".getBytes(StandardCharsets.UTF_8);
        byte[] md5_digest = Digest.finalize_digest(md5_handshake_digest);
        byte[] sha1_digest = Digest.finalize_digest(sha1_handshake_digest);
        byte[] handshake_hash = ByteUtils.concatenate(md5_digest, sha1_digest);
        byte[] verify_data = PRFUtils.PRF(protocol_version,master_secret_bytes, finished_label, handshake_hash, TLSConst.VERIFY_DATA_LEN);

//        Finished finished_handshake_message = new Finished(verify_data);
//        byte[] finished_handshake_bytes = finished_handshake_message.toBytes();
//        TLSRecord client_finished_record = new TLSRecord(ContentType.CONTENT_HANDSHAKE, finished_handshake_bytes);
//
//        byte[] finished_encrypted_bytes = TLSUtils.tls_encrypt(suite, client_finished_record, 0, send_mac_secret, send_key, send_iv);

        // client send finish
        byte[] client_encrypted_finished_bytes = SSLLog.read_data(filename, "1007-1010");
        TLSRecord client_encrypted_finished_record = TLSRecord.parse(client_encrypted_finished_bytes);
        TLSRecord client_finished_record = TLSUtilsV1_0.tls_decrypt(client_encrypted_finished_record, cipher_suite_id, 0, send_mac_secret, send_key, send_iv, null);
        byte[] client_finished_bytes = client_finished_record.toBytes();
        DisplayUtils.display_record(client_finished_bytes);
        byte[] client_finished_handshake_bytes = client_finished_record.content;

        Digest.update_digest(md5_handshake_digest, client_finished_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, client_finished_handshake_bytes);

        // server change cipher spec
        byte[] server_change_cipher_spec_bytes = SSLLog.read_data(filename, "1012-1012,1014-1014");
        TLSRecord server_change_cipher_spec_record = TLSRecord.parse(server_change_cipher_spec_bytes);
        DisplayUtils.display_record(client_change_cipher_spec_bytes);

        // server send finish
        byte[] server_encrypted_finished_bytes = SSLLog.read_data(filename, "1019-1019,1021-1023");
        TLSRecord server_encrypted_finished_record = TLSRecord.parse(server_encrypted_finished_bytes);
        TLSRecord server_finished_record = TLSUtilsV1_0.tls_decrypt(server_encrypted_finished_record, cipher_suite_id, 0, recv_mac_secret, recv_key, recv_iv, null);
        byte[] server_finished_bytes = server_finished_record.toBytes();
        DisplayUtils.display_record(server_finished_bytes);
        byte[] server_finished_handshake_bytes = server_finished_record.content;
        Finished finished_handshake = (Finished) Handshake.parse(server_finished_handshake_bytes);

        Digest.update_digest(md5_handshake_digest, server_finished_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, server_finished_handshake_bytes);

//        byte[] request_bytes = ReadUtils.read_data(filename, "1002-1004");
//        byte[] en_bytes = CBCUtils.cbc_encrypt(request_bytes, send_key, send_iv, 16, AESUtils::aes_block_encrypt);

        // client application request 1
        byte[] client_encrypted_bytes_1 = SSLLog.read_data(filename, "1050-1060");
        TLSRecord client_request_1 = decrypt(client_encrypted_bytes_1, suite, 1, send_mac_secret, send_key, send_iv);
        byte[] client_content_1 = client_request_1.content;
        System.out.println(new String(client_content_1));

        // server response 1
        byte[] server_encrypted_bytes_1 = SSLLog.read_data(filename, "1062-1062,1064-1065");
        TLSRecord server_response_1 = decrypt(server_encrypted_bytes_1, suite, 1, recv_mac_secret, recv_key, recv_iv);

        // server response 2
        byte[] server_encrypted_bytes_2 = SSLLog.read_data(filename, "1071-1071,1073-1143");
        TLSRecord server_response_2 = decrypt(server_encrypted_bytes_2, suite, 2, recv_mac_secret, recv_key, recv_iv);

        // server response 3
        byte[] server_encrypted_bytes_3 = SSLLog.read_data(filename, "1218-1218,1220-1221");
        TLSRecord server_response_e = decrypt(server_encrypted_bytes_3, suite, 3, recv_mac_secret, recv_key, recv_iv);

        // client application request 2
        byte[] client_encrypted_bytes_2 = SSLLog.read_data(filename, "1234-1236");
        TLSRecord client_request_2 = decrypt(client_encrypted_bytes_2, suite, 2, send_mac_secret, send_key, send_iv);

//        System.out.println(HexUtils.format(en_bytes, " ", 16));
//        System.out.println(HexUtils.format(encrypted_bytes, " ", 16));
    }

    public static TLSRecord decrypt(byte[] encrypted_bytes, CipherSuite suite, long seq_num, byte[] mac_secret, byte[] key, byte[] iv) {
        TLSRecord encrypted_record = TLSRecord.parse(encrypted_bytes);
        TLSRecord decrypted_record = TLSUtilsV1_0.tls_decrypt(encrypted_record, suite.id, seq_num, mac_secret, key, iv, null);
        byte[] decrypted_bytes = decrypted_record.toBytes();
        DisplayUtils.display_record(decrypted_bytes);
        return decrypted_record;
    }

    public static void print(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append("" + (b & 0xFF) + ",");
        }
        System.out.println(sb.toString());
    }

}
