package lsieun.tls.utils;

import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.crypto.sym.rc4.RC4State;
import lsieun.tls.cipher.CipherSuiteIdentifier;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.entity.handshake.Certificate;
import lsieun.tls.entity.handshake.ClientHello;
import lsieun.tls.entity.handshake.ServerHello;

public class SSLParameters {
    public CipherSuiteIdentifier cipher_suite_id = CipherSuiteIdentifier.TLS_NULL_WITH_NULL_NULL;
    public ProtocolVersion protocol_version;
    public boolean client_change_cipher;
    public boolean server_change_cipher;
    public byte[] pre_master_secret;
    public byte[] client_nonce;
    public byte[] server_nonce;
    public byte[] master_secret;
    public byte[] client_mac_secret;
    public byte[] server_mac_secret;
    public byte[] client_key;
    public byte[] server_key;
    public byte[] client_iv;
    public byte[] server_iv;
    public RC4State client_state;
    public RC4State server_state;

    public int client_seq_num = 0;
    public int server_seq_num = 0;
    public ClientHello client_hello;
    public ServerHello server_hello;
    public Certificate certificate;

    public DigestCtx md5_handshake_digest = DigestCtx.new_md5_digest();
    public DigestCtx sha1_handshake_digest = DigestCtx.new_sha1_digest();
    public DigestCtx sha256_handshake_digest = DigestCtx.new_sha256_digest();

}
