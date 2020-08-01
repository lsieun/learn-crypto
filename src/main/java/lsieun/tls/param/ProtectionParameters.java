package lsieun.tls.param;

import lsieun.crypto.sym.rc4.RC4State;
import lsieun.tls.cipher.CipherSuiteIdentifier;

public class ProtectionParameters {
    public CipherSuiteIdentifier suite = CipherSuiteIdentifier.TLS_NULL_WITH_NULL_NULL;
    public byte[] mac_secret;
    public byte[] key;
    public byte[] iv;
    public RC4State state = new RC4State();

    public long seq_num = 0;
}
