package lsieun.cert.ecdsa;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class ECDSAPublicKeyTest {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/ecdsa/ec-public.key");
        byte[] bytes = PEMUtils.read(filepath);
        ECDSAKeyUtils.parse_public_key(bytes);
    }
}
