package lsieun.tls.cipher;

import java.util.Arrays;

public enum CipherSuite {
    TLS_NULL_WITH_NULL_NULL(
            CipherSuiteIdentifier.TLS_NULL_WITH_NULL_NULL,
            KeyExchange.NULL,
            BulkCipherAlgorithm.NULL,
            OperationMode.NULL,
            MACAlgorithm.NULL
    ),
    TLS_RSA_WITH_NULL_MD5(
            CipherSuiteIdentifier.TLS_RSA_WITH_NULL_MD5,
            KeyExchange.RSA,
            BulkCipherAlgorithm.NULL,
            OperationMode.NULL,
            MACAlgorithm.MD5
    ),
    TLS_RSA_WITH_NULL_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_NULL_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.NULL,
            OperationMode.NULL,
            MACAlgorithm.SHA1
    ),
    TLS_RSA_WITH_RC4_128_MD5(
            CipherSuiteIdentifier.TLS_RSA_WITH_RC4_128_MD5,
            KeyExchange.RSA,
            BulkCipherAlgorithm.RC4,
            OperationMode.NULL,
            MACAlgorithm.MD5
    ),
    TLS_RSA_WITH_RC4_128_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_RC4_128_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.RC4,
            OperationMode.NULL,
            MACAlgorithm.SHA1
    ),
    TLS_RSA_WITH_DES_CBC_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_DES_CBC_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.DES,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.TRIPLE_DES,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    TLS_RSA_WITH_AES_128_CBC_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_AES_128_CBC_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.AES128,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    TLS_RSA_WITH_AES_256_CBC_SHA(
            CipherSuiteIdentifier.TLS_RSA_WITH_AES_256_CBC_SHA,
            KeyExchange.RSA,
            BulkCipherAlgorithm.AES256,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(
            CipherSuiteIdentifier.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            KeyExchange.DHE_RSA,
            BulkCipherAlgorithm.AES128,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(
            CipherSuiteIdentifier.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            KeyExchange.DHE_RSA,
            BulkCipherAlgorithm.AES256,
            OperationMode.CBC,
            MACAlgorithm.SHA1
    ),
    ;

    public final CipherSuiteIdentifier id;
    public final KeyExchange key_exchange;
    public final BulkCipherAlgorithm bulk_cipher_algorithm;
    public final OperationMode mode;
    public final MACAlgorithm mac_algorithm;

    CipherSuite(CipherSuiteIdentifier id,
                KeyExchange key_exchange,
                BulkCipherAlgorithm bulk_cipher_algorithm,
                OperationMode mode,
                MACAlgorithm mac_algorithm) {
        this.id = id;
        this.key_exchange = key_exchange;
        this.bulk_cipher_algorithm = bulk_cipher_algorithm;
        this.mode = mode;
        this.mac_algorithm = mac_algorithm;
    }

    public static CipherSuite valueOf(CipherSuiteIdentifier id) {
        return Arrays.stream(values()).filter(item -> item.id == id).findFirst().get();
    }
}
