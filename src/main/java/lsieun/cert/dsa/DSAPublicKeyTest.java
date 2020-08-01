package lsieun.cert.dsa;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class DSAPublicKeyTest {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/dsa/dsa-public.key");
        byte[] bytes = PEMUtils.read(filepath);
        DSAPublicKey dsa_public_key = DSAKeyUtils.parse_public_key(bytes);
        System.out.println(dsa_public_key);
    }
}
