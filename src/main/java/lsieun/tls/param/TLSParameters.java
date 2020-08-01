package lsieun.tls.param;

import lsieun.crypto.asym.dh.DHKey;
import lsieun.cert.x509.PublicKeyInfo;
import lsieun.crypto.hash.updateable.DigestCtx;
import lsieun.tls.cipher.ConnectionEnd;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.tls.key.DHKeyExchange;

public class TLSParameters {
    public ConnectionEnd connection_end;

    public ProtectionParameters pending_send_parameters = new ProtectionParameters();
    public ProtectionParameters pending_recv_parameters = new ProtectionParameters();
    public ProtectionParameters active_send_parameters = new ProtectionParameters();
    public ProtectionParameters active_recv_parameters = new ProtectionParameters();

    public ProtocolVersion protocol_version;

    // client hello and server hello
    public byte[] client_random;
    public byte[] server_random;

    public byte[] session_id = null;

    // server certificate
    public PublicKeyInfo server_public_key;


    public byte[] pre_master_secret;
    public byte[] master_secret;

    // DH public key, if supplied (either in a certificate or ephemerally)
    // Note that a server can legitimately have an RSA key for signing and
    // a DH key for key exchange (e.g. DHE_RSA)
    public DHKey server_dh_key;
    public DHKeyExchange dh_key;

    // Internal state
    public boolean peer_finished = false;

    public final DigestCtx md5_handshake_digest = DigestCtx.new_md5_digest();
    public final DigestCtx sha1_handshake_digest = DigestCtx.new_sha1_digest();
    public final DigestCtx sha256_handshake_digest = DigestCtx.new_sha256_digest();


}
