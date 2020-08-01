package lsieun.tls.utils;

import lsieun.crypto.hash.updateable.HashContextFunction;
import lsieun.crypto.sym.OperationType;
import lsieun.crypto.sym.rc4.RC4State;
import lsieun.crypto.sym.rc4.RC4Utils;
import lsieun.tls.cipher.*;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.TLSRecord;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

public class TLSUtilsV1_1 {
    public static byte[] tls_encrypt(TLSRecord tls_record, CipherSuiteIdentifier cipher_suite_id, long seq_num, byte[] mac_secret, byte[] key, byte[] iv, RC4State state) {
        ContentType content_type = tls_record.content_type;
        ProtocolVersion protocol_version = tls_record.version;
        byte[] content = tls_record.content;

        CipherSuite active_suite = CipherSuite.valueOf(cipher_suite_id);

        // (1) HMAC
        byte[] mac = new byte[0];
        if (active_suite.mac_algorithm != MACAlgorithm.NULL) {
            mac = TLSUtils.tls_mac(seq_num, content_type, protocol_version, content, mac_secret, active_suite.mac_algorithm.hash_algorithm);
        }

        byte[] data = ByteUtils.concatenate(content, mac);

        BulkCipherAlgorithm bulk_cipher_algorithm = active_suite.bulk_cipher_algorithm;
        CipherType cipher_type = bulk_cipher_algorithm.cipher_type;
        if (cipher_type == CipherType.NULL) {
            return data;
        }
        else if (bulk_cipher_algorithm == BulkCipherAlgorithm.RC4) {
            return RC4Utils.rc4_operate(data, key, state);
        }
        else {
            OperationMode mode = active_suite.mode;
            byte[] origin_iv = Arrays.copyOf(iv, iv.length);
            byte[] encrypted_bytes = TLSUtils.tls_bulk_operate(data, OperationType.ENCRYPT, mode, bulk_cipher_algorithm, key, iv);
            return ByteUtils.concatenate(origin_iv, encrypted_bytes);
        }
    }

    public static TLSRecord tls_decrypt(TLSRecord tls_record, CipherSuiteIdentifier cipher_suite_id, long seq_num, byte[] mac_secret, byte[] key, byte[] iv, RC4State state) {
        ContentType content_type = tls_record.content_type;
        ProtocolVersion protocol_version = tls_record.version;
        byte[] encrypted_content = tls_record.content;


        CipherSuite active_suite = CipherSuite.valueOf(cipher_suite_id);


        byte[] decrypted_bytes;
        BulkCipherAlgorithm bulk_cipher_algorithm = active_suite.bulk_cipher_algorithm;
        if (bulk_cipher_algorithm == BulkCipherAlgorithm.NULL) {
            decrypted_bytes = encrypted_content;
        }
        else if (bulk_cipher_algorithm == BulkCipherAlgorithm.RC4) {
            decrypted_bytes = RC4Utils.rc4_operate(encrypted_content, key, state);
        }
        else {
            OperationMode mode = active_suite.mode;
            int block_size = active_suite.bulk_cipher_algorithm.block_size;
            iv = Arrays.copyOf(encrypted_content, block_size);
            byte[] removed_iv_content = Arrays.copyOfRange(encrypted_content, block_size, encrypted_content.length);
            decrypted_bytes = TLSUtils.tls_bulk_operate(removed_iv_content, OperationType.DECRYPT, mode, bulk_cipher_algorithm, key, iv);
        }

        MACAlgorithm mac_algorithm = active_suite.mac_algorithm;
        if (mac_algorithm == MACAlgorithm.NULL) {
            return new TLSRecord(content_type, protocol_version, decrypted_bytes);
        }
        else {
            int decrypted_length = decrypted_bytes.length;
            HashContextFunction hash_algorithm = mac_algorithm.hash_algorithm;
            int hash_size = mac_algorithm.hash_size;

            int content_length = decrypted_length - hash_size;

            byte[] content = Arrays.copyOf(decrypted_bytes, content_length);
            byte[] received_hmac = Arrays.copyOfRange(decrypted_bytes, content_length, content_length + hash_size);


            byte[] mac = TLSUtils.tls_mac(seq_num, content_type, protocol_version, content, mac_secret, hash_algorithm);

            if (!Arrays.equals(received_hmac, mac)) {
                throw new RuntimeException("hmac not equals");
            }

            return new TLSRecord(content_type, protocol_version, content);
        }

    }
}
