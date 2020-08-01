package lsieun.cert.asn1;

import lsieun.utils.FileUtils;

import java.util.List;

public class ASN1TestPEMBitString {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/dsa/dsa-public.key");
        byte[] bytes = PEMUtils.read(filepath);
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);
        ASN1Struct asn1_subject_public_key = asn1_seq.children.get(1);
        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_subject_public_key);
        List<ASN1Struct> list = ASN1Utils.parse_der(bit_string_data);
        ASN1Utils.show_raw(list);
    }
}
