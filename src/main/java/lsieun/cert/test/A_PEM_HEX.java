package lsieun.cert.test;

import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

public class A_PEM_HEX {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/ecdsa/signed_certificate.pem");
        byte[] decode_bytes = PEMUtils.read(filepath);
        String result = HexUtils.format(decode_bytes, HexFormat.FORMAT_FF_SPACE_FF_16);
        System.out.println(result);
    }
}
