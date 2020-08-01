package lsieun.cert.ecdsa;

import lsieun.crypto.asym.ecc.Point;
import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;
import lsieun.cert.cst.ObjectIdentifier;
import lsieun.utils.ByteDashboard;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

public class ECDSAPublicKey {
    public final ObjectIdentifier oid;
    public Point public_key;

    public ECDSAPublicKey(ObjectIdentifier oid, Point public_key) {
        this.oid = oid;
        this.public_key = public_key;
    }

    public static ECDSAPublicKey parse(ASN1Struct asn1_algorithm_parameters, ASN1Struct asn1_subject_public_key) {
        ObjectIdentifier curve = ObjectIdentifier.valueOf(asn1_algorithm_parameters.data);

        byte[] bit_string_data = ASN1Utils.get_bit_string_data(asn1_subject_public_key);

        if (bit_string_data.length != 65) {
            throw new RuntimeException("length is not 65, is " + bit_string_data.length);
        }

        ByteDashboard bd = new ByteDashboard(bit_string_data);
        byte first_byte = bd.next();
        if (first_byte != 4) {
            throw new RuntimeException("Something is Wrong!");
        }

        byte[] x_32_bytes = bd.nextN(32);
        byte[] y_32_bytes = bd.nextN(32);

        System.out.println(HexUtils.format(x_32_bytes, HexFormat.FORMAT_FF_SPACE_FF));
        System.out.println(HexUtils.format(y_32_bytes, HexFormat.FORMAT_FF_SPACE_FF));

        BigInteger x = new BigInteger(1, x_32_bytes);
        BigInteger y = new BigInteger(1, y_32_bytes);


        Point public_key = new Point(x, y);

        return new ECDSAPublicKey(curve, public_key);
    }
}
