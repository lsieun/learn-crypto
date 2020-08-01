package lsieun.cert.asn1;

import lsieun.utils.FileUtils;

import java.util.List;

@SuppressWarnings("Duplicates")
public class ASN1TestPEM {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/www/ec_tmall.pem");
        List<ASN1Struct> list = ASN1Utils.parse_pem(filepath);
        ASN1Utils.show_human_readable(list);
    }
}
