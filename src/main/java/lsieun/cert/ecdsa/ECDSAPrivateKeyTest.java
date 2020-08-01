package lsieun.cert.ecdsa;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class ECDSAPrivateKeyTest {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/ecdsa/ec.key");
        byte[] bytes = PEMUtils.read(filepath);
        ECDSAPrivateKey ecdsa_private_key = ECDSAKeyUtils.parse_private_key(bytes);

    }
}
