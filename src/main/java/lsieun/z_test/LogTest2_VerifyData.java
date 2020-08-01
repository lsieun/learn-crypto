package lsieun.z_test;

import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.utils.DisplayUtils;
import lsieun.tls.utils.SecretUtils;
import lsieun.tls.utils.TLSUtils;
import lsieun.utils.ByteDashboard;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;
import lsieun.utils.SSLLog;

public class LogTest2_VerifyData {
    public static void main(String[] args) {
        ProtocolVersion protocol_version = ProtocolVersion.TLSv1_2;
        CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;

        String filename = "log/tlsv1.2_dhe_rsa_with_aes_256_cbc_sha.txt";
        byte[] pre_master_secret = SSLLog.read_data(filename, "958-960");
        byte[] client_random = SSLLog.read_data(filename, "963-964");
        byte[] server_random = SSLLog.read_data(filename, "966-967");
        byte[] master_secret = SecretUtils.calculate_master_secret(protocol_version, pre_master_secret, client_random, server_random);
        byte[] key_material = SecretUtils.calculate_keys(protocol_version, 136, master_secret, client_random, server_random);

        ByteDashboard bd = new ByteDashboard(key_material);
        byte[] client_mac_secret = bd.nextN(20);
        byte[] server_mac_secret = bd.nextN(20);
        byte[] client_key = bd.nextN(32);
        byte[] server_key = bd.nextN(32);
        byte[] client_iv = bd.nextN(16);
        byte[] server_iv = bd.nextN(16);
//        System.out.println(HexUtils.format(client_mac_secret, " ", 16));
//        System.out.println(HexUtils.format(server_mac_secret, " ", 16));
//        System.out.println(HexUtils.format(client_key, " ", 16));
//        System.out.println(HexUtils.format(server_key, " ", 16));

//        System.out.println("client iv:");
//        System.out.println(HexUtils.format(client_iv, " ", 16));
//        System.out.println();

        byte[] verify_data = HexUtils.parse("AA 00 6F E3 04 F5 8F 30 EC DA F6 A3", HexFormat.FORMAT_FF_SPACE_FF);


        byte[] client_finished_bytes = SSLLog.read_data(filename, "1007-1011");

        TLSRecord tls_record = TLSRecord.parse(client_finished_bytes);
        TLSRecord tls_decrypted_record = TLSUtils.tls_decrypt(tls_record, CipherSuiteIdentifier.TLS_RSA_WITH_AES_256_CBC_SHA, 0, client_mac_secret, client_key, client_iv, null);
        byte[] bytes = tls_decrypted_record.toBytes();
        DisplayUtils.display_record(bytes);
    }
}
