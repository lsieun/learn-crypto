package lsieun.z_test;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.crypto.asym.rsa.RSAUtils;
import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.cipher.HashAlgorithm;
import lsieun.tls.cipher.SignatureAlgorithm;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.handshake.Certificate;
import lsieun.tls.entity.handshake.Handshake;
import lsieun.tls.entity.handshake.HandshakeType;
import lsieun.tls.utils.DisplayUtils;
import lsieun.utils.*;

import java.util.Formatter;
import java.util.List;

public class LogTest3_ServerKeyExchange {
    public static void main(String[] args) {
        ProtocolVersion protocol_version = ProtocolVersion.TLSv1_2;
        CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;

        String filename = "log/tlsv1.2_dhe_rsa_with_aes_256_cbc_sha.txt";
        byte[] client_random = SSLLog.read_data(filename, "918-919");
        byte[] server_random = SSLLog.read_data(filename, "921-922");

        byte[] total_bytes = SSLLog.read_data(filename, "48-278");

        ByteDashboard bd = new ByteDashboard(total_bytes);
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);

        byte[] server_hello_length_bytes = bd.peekN(1, 3);
        int server_hello_length = ByteUtils.toInt(server_hello_length_bytes);
        byte[] server_hello_bytes = bd.nextN(server_hello_length + 4);
        DisplayUtils.process_server_hello(server_hello_bytes, fm);

        byte[] certificate_length_bytes = bd.peekN(1, 3);
        int certificate_length = ByteUtils.toInt(certificate_length_bytes);
        byte[] certificate_bytes = bd.nextN(certificate_length + 4);
        Certificate cert = (Certificate) Handshake.parse(certificate_bytes);
        DisplayUtils.process_certificate(certificate_bytes, fm);

        byte[] server_key_exchange_length_bytes = bd.peekN(1, 3);
        int server_key_exchange = ByteUtils.toInt(server_key_exchange_length_bytes);
        byte[] server_key_exchange_bytes = bd.nextN(server_key_exchange + 4);

        RSAKey rsa_pub_key = cert.cert_list.get(0).tbs_certificate.subjectPublicKeyInfo.rsa_public_key.toKey();

        ByteDashboard bd2 = new ByteDashboard(server_key_exchange_bytes);
        test(bd2, fm, rsa_pub_key, client_random, server_random);

        System.out.println(sb.toString());
    }

    public static void test(ByteDashboard bd, Formatter fm, RSAKey rsa_pub_key, byte[] client_random, byte[] server_random) {
        byte[] handshake_type_bytes = bd.nextN(1);
        byte[] length_bytes = bd.nextN(3);

        HandshakeType handshake_type = HandshakeType.valueOf(ByteUtils.toInt(handshake_type_bytes));
        int length = ByteUtils.toInt(length_bytes);

        String handshake_type_hex = HexUtils.format(handshake_type_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        String length_hex = HexUtils.format(length_bytes, HexFormat.FORMAT_FF_SPACE_FF);

        fm.format("Handshake Type: %s (%s)%n", handshake_type, handshake_type_hex);
        fm.format("Length: %d (%s)%n", length, length_hex);

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

        byte[] two_bytes = bd.nextN(2);
        byte hash_algorithm_val = two_bytes[0];
        byte signature_algorithm_val = two_bytes[1];
        HashAlgorithm hash_algorithm = HashAlgorithm.valueOf(hash_algorithm_val);
        SignatureAlgorithm signature_algorithm = SignatureAlgorithm.valueOf(signature_algorithm_val);
        fm.format("    Hash Algorithm: %s%n", hash_algorithm);
        fm.format("    Signature Algorithm: %s%n", signature_algorithm);

        byte[] signature_length_bytes = bd.nextN(2);
        int signature_length = ByteUtils.toInt(signature_length_bytes);
        String signature_length_hex = HexUtils.format(signature_length_bytes, HexFormat.FORMAT_FF_SPACE_FF);
        byte[] signature_bytes = bd.nextN(signature_length);
        String signature_hex = HexUtils.format(signature_bytes, " ", 32);
        fm.format("    Signature Length: %d (%s)%n", signature_length, signature_length_hex);
        fm.format("    Signature: %s%n", signature_hex);

        // hash: md5 and sha1
        byte[] p_total_bytes = ByteUtils.concatenate(p_length_bytes, p_bytes);
        byte[] g_total_bytes = ByteUtils.concatenate(g_length_bytes, g_bytes);
        byte[] pub_key_total_bytes = ByteUtils.concatenate(pub_key_length_bytes, pub_key_bytes);
        byte[] message = ByteUtils.concatenate(p_total_bytes, g_total_bytes, pub_key_total_bytes);
        byte[] input = ByteUtils.concatenate(client_random, server_random, message);

        byte[] digest = SHA256Utils.sha256_hash(input);
        fm.format("signature: %s%n%n", HexUtils.format(digest, HexFormat.FORMAT_FF_SPACE_FF));

        fm.format("===========%n");
        byte[] decrypted_bytes = RSAUtils.rsa_decrypt(signature_bytes, rsa_pub_key);
        fm.format(HexUtils.format(decrypted_bytes, " ", 16));
        List<ASN1Struct> list = ASN1Utils.parse_der(decrypted_bytes);
        ASN1Utils.show_raw(list);
    }
}
