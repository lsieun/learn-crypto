package lsieun.cert.x509;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;

public class SignatureValue {
    public final byte[] data;

    public SignatureValue(byte[] data) {
        this.data = data;
    }

    public static SignatureValue parse(ASN1Struct asn1_signature_value) {
        byte[] bytes = ASN1Utils.get_bit_string_data(asn1_signature_value);
        return new SignatureValue(bytes);
    }
}
