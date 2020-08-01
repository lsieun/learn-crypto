package lsieun.tls.entity.handshake;

import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.handshake.ext.Extension;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static lsieun.tls.cipher.CipherSuiteIdentifier.*;

public class ClientHello extends Handshake {
    public final ProtocolVersion client_version;
    public final TLSRandom random;
    public final byte[] session_id;
    public final CipherSuiteIdentifier[] cipher_suites;
    public final byte[] compression_methods;
    public final List<Extension> extension_list = new ArrayList<>();

    public ClientHello(ProtocolVersion client_version,
                       TLSRandom random,
                       byte[] session_id,
                       CipherSuiteIdentifier[] cipher_suites,
                       byte[] compression_methods) {
        super(HandshakeType.CLIENT_HELLO);
        this.client_version = client_version;
        this.random = random;
        this.session_id = session_id;
        this.cipher_suites = cipher_suites;
        this.compression_methods = compression_methods;
    }

    public byte[] getData() throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();

        bao.write(client_version.major); // version
        bao.write(client_version.minor);

        bao.write(random.toBytes()); // random

        bao.write(session_id.length); // session
        bao.write(session_id);

        int cipher_suites_length = cipher_suites.length * 2; // cipher suite
        bao.write((cipher_suites_length >> 8) & 0xFF);
        bao.write(cipher_suites_length & 0xFF);
        for (CipherSuiteIdentifier item : cipher_suites) {
            int hi = item.val >> 8 & 0xFF;
            int lo = item.val & 0xFF;
            bao.write(hi);
            bao.write(lo);
        }

        int compression_method_length = compression_methods.length; // compression_method
        bao.write(compression_method_length);
        bao.write(compression_methods);

        return bao.toByteArray();
    }

    @SuppressWarnings("Duplicates")
    public static ClientHello fromBytes(byte[] data) {
        try {
            ByteDashboard bd = new ByteDashboard(data);
            byte major = bd.next();
            byte minor = bd.next();

            ProtocolVersion version = ProtocolVersion.valueOf(major, minor);
            TLSRandom random = TLSRandom.fromBytes(bd.nextN(32));
            byte session_id_length = bd.next();
            byte[] session_id = bd.nextN(session_id_length);
            int cipher_suite_length = ByteUtils.toInt(bd.nextN(2));
            byte[] cipher_suite_bytes = bd.nextN(cipher_suite_length);
            int cipher_suite_count = cipher_suite_length / 2;
            CipherSuiteIdentifier[] cipher_suites = new CipherSuiteIdentifier[cipher_suite_count];
            for (int i = 0; i < cipher_suite_count; i++) {
                byte hi = cipher_suite_bytes[2 * i];
                byte lo = cipher_suite_bytes[2 * i + 1];
                int val = (hi & 0xFF) << 8 | (lo & 0xFF);
                cipher_suites[i] = CipherSuiteIdentifier.valueOf(val);
            }

            byte compression_method_length = bd.next();
            byte[] compression_methods = bd.nextN(compression_method_length);

            ClientHello client_hello = new ClientHello(version, random, session_id, cipher_suites, compression_methods);
            if (bd.hasNext()) {
                int extensions_length = bd.nextInt(2);
                byte[] extensions_bytes = bd.nextN(extensions_length);
                List<Extension> ext_list = Extension.parse_list(extensions_bytes);
                client_hello.extension_list.addAll(ext_list);
            }
            return client_hello;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static ClientHello getInstance() {
        byte[] session_id = new byte[0];
        return getInstance(session_id);
    }

    public static ClientHello getInstance(byte[] session_id) {
        int major = TLSConst.TLS_VERSION_MAJOR;
        int minor = TLSConst.TLS_VERSION_MINOR;

        int local_time = (int) (System.currentTimeMillis() / 1000);
        CipherSuiteIdentifier[] cipher_suites = {
//                TLS_RSA_WITH_RC4_128_SHA,
                TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//                TLS_RSA_WITH_AES_256_CBC_SHA,
//              TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        };
        byte[] compression_methods = new byte[]{0};

        ProtocolVersion client_version = ProtocolVersion.valueOf(major, minor);
        TLSRandom random = new TLSRandom(local_time);

        return new ClientHello(client_version, random, session_id, cipher_suites, compression_methods);
    }
}
