package lsieun.cert.x509;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.asn1.PEMUtils;
import lsieun.utils.FileUtils;

public class TestSignedData {
    public static void main(String[] args) {
        String public_key_filepath = FileUtils.getFilePath("cert/ecdsa/ec-public.key");
        byte[] public_key_bytes = PEMUtils.read(public_key_filepath);
        ASN1Struct asn1_key = ASN1Utils.parse_der(public_key_bytes).get(0);
        PublicKeyInfo public_key_info = PublicKeyInfo.parse(asn1_key);

        String signed_data_filepath = FileUtils.getFilePath("cert/ecdsa/signed_certificate.pem");
        byte[] signed_data_bytes = PEMUtils.read(signed_data_filepath);
        boolean flag = X509Utils.validate_signed_data(signed_data_bytes, public_key_info);
        System.out.println(flag);
    }
}
