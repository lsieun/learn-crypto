package lsieun.cert.test;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.ByteUtils;
import lsieun.utils.FileUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.List;

public class E_TBS_Certificate_Hash {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Workspace/tmp/www_example_org.der";
        byte[] bytes = FileUtils.readBytes(filepath);
        List<ASN1Struct> list = ASN1Utils.parse_der(bytes);
        ASN1Struct asn1_tbs_certificate = list.get(0).children.get(0);
        byte[] header = asn1_tbs_certificate.header;
        byte[] data = asn1_tbs_certificate.data;
        byte[] input = ByteUtils.concatenate(header, data);
        byte[] digest = SHA256Utils.sha256_hash(input);
        String result = HexUtils.format(digest, HexFormat.FORMAT_FF_SPACE_FF);
        System.out.println(result);
    }
}
