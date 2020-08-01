package lsieun.cert.signature;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

import java.util.List;

public class ECDSA_SignatureValue {
    public static void main(String[] args) {
        String filepath = FileUtils.getFilePath("cert/ecdsa/signed_certificate.pem");
        byte[] bytes = PEMUtils.read(filepath);
        ASN1Struct asn1_seq = ASN1Utils.parse_der(bytes).get(0);

        ASN1Struct asn1_signature_value = asn1_seq.children.get(2);
        byte[] bit_string_bytes = ASN1Utils.get_bit_string_data(asn1_signature_value);

        List<ASN1Struct> list = ASN1Utils.parse_der(bit_string_bytes);
        ASN1Utils.show_raw(list);
    }
}
