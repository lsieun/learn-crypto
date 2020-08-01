package lsieun.cert.asn1;

import java.util.List;

public class ASN1TestDER {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Workspace/tmp/cert.der";
        List<ASN1Struct> list = ASN1Utils.parse_der(filepath);
        ASN1Utils.show_human_readable(list);
    }
}
