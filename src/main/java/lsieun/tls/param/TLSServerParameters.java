package lsieun.tls.param;

import lsieun.cert.asn1.PEMUtils;
import lsieun.cert.cst.AlgorithmIdentifier;
import lsieun.cert.x509.PrivateKeyInfo;
import lsieun.utils.FileUtils;

public class TLSServerParameters extends TLSParameters {
    public boolean got_client_hello = false;
    public PrivateKeyInfo private_key_info;

    public TLSServerParameters() {
        String filepath = FileUtils.getFilePath("cert/rsa/rsa-private.key");
        byte[] bytes = PEMUtils.read(filepath);
        this.private_key_info = PrivateKeyInfo.parse(AlgorithmIdentifier.RSA, bytes);
    }
}
