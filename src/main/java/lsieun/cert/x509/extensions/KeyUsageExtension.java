package lsieun.cert.x509.extensions;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.asn1.ASN1Utils;

public class KeyUsageExtension extends Extension {
    public static final int BIT_DIGITAL_SIGNATURE = 0;
    public static final int BIT_NON_REPUDIATION = 1;
    public static final int BIT_KEY_ENCIPHERMENT = 2;
    public static final int BIT_DATA_ENCIPHERMENT = 3;
    public static final int BIT_KEY_AGREEMENT = 4;
    public static final int BIT_KEY_CERT_SIGN = 5;
    public static final int BIT_CRL_SIGN = 6;
    public static final int BIT_ENCIPHER_ONLY = 7;
    public static final int BIT_DECIPHER_ONLY = 8;

    public final boolean isDigitalSignature;
    public final boolean isNonRepudiation;
    public final boolean isKeyEncipherment;
    public final boolean isDataEncipherment;
    public final boolean isKeyAgreement;
    public final boolean isKeyCertSign;
    public final boolean isCRLSign;
    public final boolean isEncipherOnly;
    public final boolean isDecipherOnly;

    public KeyUsageExtension(byte[] oid_bytes, boolean critical, byte[] data,
                             boolean isDigitalSignature,
                             boolean isNonRepudiation,
                             boolean isKeyEncipherment,
                             boolean isDataEncipherment,
                             boolean isKeyAgreement,
                             boolean isKeyCertSign,
                             boolean isCRLSign,
                             boolean isEncipherOnly,
                             boolean isDecipherOnly) {
        super(oid_bytes, critical, data);
        this.isDigitalSignature = isDigitalSignature;
        this.isNonRepudiation = isNonRepudiation;
        this.isKeyEncipherment = isKeyEncipherment;
        this.isDataEncipherment = isDataEncipherment;
        this.isKeyAgreement = isKeyAgreement;
        this.isKeyCertSign = isKeyCertSign;
        this.isCRLSign = isCRLSign;
        this.isEncipherOnly = isEncipherOnly;
        this.isDecipherOnly = isDecipherOnly;
    }

    public static KeyUsageExtension parse_key_usage_extension(byte[] oid_bytes, boolean critical, byte[] data) {
        ASN1Struct asn1_key_usage = ASN1Utils.parse_der(data).get(0);
        if (asn1_key_usage.tag != 3) {
            throw new RuntimeException("tag is Not ASN1_BIT_STRING");
        }

        boolean isDigitalSignature = asn1_get_bit(asn1_key_usage.data, BIT_DIGITAL_SIGNATURE);
        boolean isNonRepudiation = asn1_get_bit(asn1_key_usage.data, BIT_NON_REPUDIATION);
        boolean isKeyEncipherment = asn1_get_bit(asn1_key_usage.data, BIT_KEY_ENCIPHERMENT);
        boolean isDataEncipherment = asn1_get_bit(asn1_key_usage.data, BIT_DATA_ENCIPHERMENT);
        boolean isKeyAgreement = asn1_get_bit(asn1_key_usage.data, BIT_KEY_AGREEMENT);
        boolean isKeyCertSign = asn1_get_bit(asn1_key_usage.data, BIT_KEY_CERT_SIGN);
        boolean isCRLSign = asn1_get_bit(asn1_key_usage.data, BIT_CRL_SIGN);
        boolean isEncipherOnly = asn1_get_bit(asn1_key_usage.data, BIT_ENCIPHER_ONLY);
        boolean isDecipherOnly = asn1_get_bit(asn1_key_usage.data, BIT_DECIPHER_ONLY);

        return new KeyUsageExtension(oid_bytes, critical, data,
                isDigitalSignature,
                isNonRepudiation,
                isKeyEncipherment,
                isDataEncipherment,
                isKeyAgreement,
                isKeyCertSign,
                isCRLSign,
                isEncipherOnly,
                isDecipherOnly);
    }

    public static boolean asn1_get_bit(byte[] bit_string, int bit) {
        if (bit < 0) return false;
        if (bit >= (bit_string.length - 1) * 8) return false;
        int index = 1 + bit / 8;
        int mask = (0x80 >> (bit % 8));
        return (bit_string[index] & mask) == mask;
    }
}
