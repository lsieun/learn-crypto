package lsieun.cert.rsa;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class RSAPublicKeyTest {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/rsa/rsa-public.key");
        byte[] bytes = PEMUtils.read(filepath);
        RSAKeyUtils.parse_public_key(bytes);
    }
}
