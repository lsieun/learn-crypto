package lsieun.z_test;

import lsieun.crypto.hash.updateable.Digest;
import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.handshake.Certificate;
import lsieun.tls.entity.handshake.ClientHello;
import lsieun.tls.entity.handshake.Handshake;
import lsieun.tls.entity.handshake.ServerHello;
import lsieun.tls.utils.*;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;
import lsieun.utils.SSLLog;

import java.math.BigInteger;

public class RSA_DHE_Test {
    public static final String filename = "log/baidu_tlsv1_dhe_rsa.txt";

    public static void main(String[] args) {
        DigestCtx md5_handshake_digest = DigestCtx.new_md5_digest();
        DigestCtx sha1_handshake_digest = DigestCtx.new_sha1_digest();

        // client hello
        byte[] client_hello_record_bytes = SSLLog.read_data(filename, "36-42");
        TLSRecord client_hello_record = TLSRecord.parse(client_hello_record_bytes);
        DisplayUtils.display_record(client_hello_record_bytes);
        byte[] client_hello_handshake_bytes = client_hello_record.content;
        ClientHello client_hello = (ClientHello) Handshake.parse(client_hello_handshake_bytes);
        byte[] client_random_bytes = client_hello.random.toBytes();

        Digest.update_digest(md5_handshake_digest, client_hello_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, client_hello_handshake_bytes);

        // server hello
        byte[] server_hello_record_bytes = SSLLog.read_data(filename, "44-44,46-50");
        TLSRecord server_hello_record = TLSRecord.parse(server_hello_record_bytes);
        DisplayUtils.display_record(server_hello_record_bytes);
        byte[] server_hello_handshake_bytes = server_hello_record.content;
        ServerHello server_hello = (ServerHello) Handshake.parse(server_hello_handshake_bytes);
        byte[] server_random_bytes = server_hello.random.toBytes();

        Digest.update_digest(md5_handshake_digest, server_hello_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, server_hello_handshake_bytes);

        // server certificate
        byte[] certificate_record_bytes = SSLLog.read_data(filename, "81-81,83-317");
        TLSRecord certificate_record = TLSRecord.parse(certificate_record_bytes);
        DisplayUtils.display_record(certificate_record_bytes);
        byte[] certificate_handshake_bytes = certificate_record.content;
        Certificate cert_handshake = (Certificate) Handshake.parse(certificate_handshake_bytes);

        Digest.update_digest(md5_handshake_digest, certificate_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, certificate_handshake_bytes);

        // server key exchange
        byte[] server_key_exchange_record_bytes = SSLLog.read_data(filename, "902-902,904-924");
        TLSRecord server_key_exchange_record = TLSRecord.parse(server_key_exchange_record_bytes);
        DisplayUtils.display_record(server_key_exchange_record_bytes);
        byte[] server_key_exchange_handshake_bytes = server_key_exchange_record.content;
        BigInteger Gx = new BigInteger("37448807308054059848411404121575243526602298782465820269518317044997565191338");
        BigInteger Gy = new BigInteger("47453391708943222353961355361731668491114341962533090963842887581827747725798");

        Digest.update_digest(md5_handshake_digest, server_key_exchange_handshake_bytes);
        Digest.update_digest(sha1_handshake_digest, server_key_exchange_handshake_bytes);

        {
            ByteDashboard bd = new ByteDashboard(server_key_exchange_handshake_bytes);
            bd.skip(4);
            byte[] curve_type_bytes = bd.nextN(1);
            byte[] named_curve_bytes = bd.nextN(2);
            byte[] public_key_length_bytes = bd.nextN(1);
            int public_key_length = ByteUtils.toInt(public_key_length_bytes);
            byte[] public_key_bytes = bd.nextN(public_key_length);

            byte[] signature_length_bytes = bd.nextN(2);
            int signature_length = ByteUtils.toInt(signature_length_bytes);
            byte[] signature_bytes = bd.nextN(signature_length);


            byte[] total_bytes0 = ByteUtils.concatenate(client_random_bytes, server_random_bytes);
            byte[] total_bytes1 = ByteUtils.concatenate(curve_type_bytes, named_curve_bytes);
            byte[] total_bytes2 = ByteUtils.concatenate(public_key_length_bytes, public_key_bytes);
            byte[] message_bytes = ByteUtils.concatenate(total_bytes1, total_bytes2);
//            byte[] total_bytes = ByteUtils.concatenate(total_bytes0, total_bytes1, total_bytes2);

//            System.out.println(HexUtils.format(total_bytes, " ", 16));
//            System.out.println();
//
//            byte[] md5_bytes = MD5Utils.md5_hash(total_bytes);
//            byte[] sha1_bytes = SHA1Utils.sha1_hash(total_bytes);
//            System.out.println(HexUtils.format(md5_bytes, " ", 16));
//            System.out.println(HexUtils.format(sha1_bytes, " ", 16));
//            System.out.println();
//
//            final byte[] decrypted_bytes = RSAUtils.rsa_decrypt(signature_bytes, cert_handshake.cert_list.get(0).tbs_certificate.subjectPublicKeyInfo.rsa_public_key.toKey());
//            System.out.println(HexUtils.format(decrypted_bytes, " ", 16));

            boolean flag = TLSUtilsV1_0.verify_server_key_exchange_signature(client_random_bytes, server_random_bytes, message_bytes, cert_handshake.cert_list.get(0).tbs_certificate.subjectPublicKeyInfo.rsa_public_key.toKey(), signature_bytes);
            System.out.println(flag);

        }

//        // server hello done
//        byte[] server_hello_done_bytes = ReadUtils.read_data(filename, "965-965,967-967");
//        TLSRecord server_hello_done_record = TLSRecord.parse(server_hello_done_bytes);
//        DisplayUtils.display_record(server_hello_done_bytes);
//        byte[] server_hello_done_handshake_bytes = server_hello_done_record.content;
//
//        Digest.update_digest(md5_handshake_digest, server_hello_done_handshake_bytes);
//        Digest.update_digest(sha1_handshake_digest, server_hello_done_handshake_bytes);
//
//        // client key exchange
//        byte[] client_key_exchange_bytes = ReadUtils.read_data(filename, "997-1001");
//        TLSRecord client_key_exchange_record = TLSRecord.parse(client_key_exchange_bytes);
//        DisplayUtils.display_record(client_key_exchange_bytes);
//        byte[] client_key_exchange_handshake_bytes = client_key_exchange_record.content;
//
//        Digest.update_digest(md5_handshake_digest, client_key_exchange_handshake_bytes);
//        Digest.update_digest(sha1_handshake_digest, client_key_exchange_handshake_bytes);
//
//        // pre master secret --> master secret
//        byte[] pre_master_secret_bytes = ReadUtils.read_data(filename, "1004-1005");
//        BigInteger pre_master_secret = new BigInteger(1, pre_master_secret_bytes);
//        byte[] master_secret_bytes = SecretUtils.calculate_master_secret(pre_master_secret_bytes, client_random_bytes, server_random_bytes);
//
//        // key material
//        CipherSuite suite = CipherSuite.valueOf(CipherSuiteIdentifier.TLS_RSA_WITH_AES_128_CBC_SHA);
//        int key_block_length = suite.hash_size * 2 + suite.key_size * 2 + suite.iv_size * 2;
//        byte[] label = "key expansion".getBytes(StandardCharsets.UTF_8);
//        byte[] seed = ByteUtils.concatenate(server_random_bytes, client_random_bytes);
//        byte[] key_block = PRFUtils.PRF(master_secret_bytes, label, seed, key_block_length);
//
//        ByteDashboard bd = new ByteDashboard(key_block);
//        byte[] send_mac_secret = bd.nextN(suite.hash_size);
//        byte[] recv_mac_secret = bd.nextN(suite.hash_size);
//        byte[] send_key = bd.nextN(suite.key_size);
//        byte[] recv_key = bd.nextN(suite.key_size);
//        byte[] send_iv = bd.nextN(suite.iv_size);
//        byte[] recv_iv = bd.nextN(suite.iv_size);
//
//        System.out.println("Client MAC Secret: " + HexUtils.format(send_mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Server MAC Secret: " + HexUtils.format(recv_mac_secret, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Client key: " + HexUtils.format(send_key, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Server key: " + HexUtils.format(recv_key, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Client IV: " + HexUtils.format(send_iv, HexFormat.FORMAT_FF_SPACE_FF));
//        System.out.println("Server IV: " + HexUtils.format(recv_iv, HexFormat.FORMAT_FF_SPACE_FF));
//
//        // client change cipher spec
//        byte[] client_change_cipher_spec_bytes = ReadUtils.read_data(filename, "1037-1037");
//        TLSRecord client_change_cipher_spec_record = TLSRecord.parse(client_change_cipher_spec_bytes);
//        DisplayUtils.display_record(client_change_cipher_spec_bytes);
//
//        // client finish verify data
//        byte[] finished_label = "client finished".getBytes(StandardCharsets.UTF_8);
//        byte[] md5_digest = Digest.finalize_digest(md5_handshake_digest);
//        byte[] sha1_digest = Digest.finalize_digest(sha1_handshake_digest);
//        byte[] handshake_hash = ByteUtils.concatenate(md5_digest, sha1_digest);
//        byte[] verify_data = PRFUtils.PRF(master_secret_bytes, finished_label, handshake_hash, TLSConst.VERIFY_DATA_LEN);
//
////        EllipticCurve ec = EllipticCurve.P256;
////        final Point target_point = ECCUtils.multiply_point(ec.G, pre_master_secret, ec.a, ec.p);
////        System.out.println(target_point.x);
////        System.out.println(target_point.y);
//
//        // client send finish
//        byte[] client_encrypted_finished_bytes = ReadUtils.read_data(filename, "1052-1055");
//        TLSRecord client_encrypted_finished_record = TLSRecord.parse(client_encrypted_finished_bytes);
//        TLSRecord client_finished_record = TLSUtils.tls_decrypt(client_encrypted_finished_record, suite, 0, send_mac_secret, send_key, send_iv);
//        byte[] client_finished_bytes = client_finished_record.toBytes();
//        DisplayUtils.display_record(client_finished_bytes);
//        byte[] client_finished_handshake_bytes = client_finished_record.content;
//
//        Digest.update_digest(md5_handshake_digest, client_finished_handshake_bytes);
//        Digest.update_digest(sha1_handshake_digest, client_finished_handshake_bytes);
//
//        System.out.println(HexUtils.format(client_finished_handshake_bytes, " ", 16));
    }
}
