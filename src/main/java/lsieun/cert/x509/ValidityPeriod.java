package lsieun.cert.x509;

import lsieun.cert.asn1.ASN1Converter;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.utils.DateUtils;

import java.util.Date;
import java.util.List;

public class ValidityPeriod {
    public final Date notBefore;
    public final Date notAfter;

    public ValidityPeriod(Date notBefore, Date notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    @Override
    public String toString() {
        return "ValidityPeriod {" +
                "notBefore='" + DateUtils.format(notBefore) + "'" +
                ", notAfter='" + DateUtils.format(notAfter) + "'" +
                '}';
    }

    public static ValidityPeriod parse(ASN1Struct struct) {
        List<ASN1Struct> children = struct.children;
        ASN1Struct asn1_not_before = children.get(0);
        ASN1Struct asn1_not_after = children.get(1);

        Date notBefore = ASN1Converter.toDate(asn1_not_before);
        Date notAfter = ASN1Converter.toDate(asn1_not_after);

        return new ValidityPeriod(notBefore, notAfter);
    }
}
