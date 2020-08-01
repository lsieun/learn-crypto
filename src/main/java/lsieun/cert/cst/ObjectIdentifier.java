package lsieun.cert.cst;

import lsieun.cert.oid.OIDUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Optional;

public enum ObjectIdentifier {
    RSAEncryption("2A 86 48 86 F7 0D 01 01 01"),
    MD5_With_RSA("2A 86 48 86 F7 0D 01 01 04"),
    SHA1_With_RSA("2A 86 48 86 F7 0D 01 01 05"),
    SHA256_With_RSA("2A 86 48 86 F7 0D 01 01 0B"),
    SHA384_With_RSA("2A 86 48 86 F7 0D 01 01 0C"),
    SHA512_With_RSA("2A 86 48 86 F7 0D 01 01 0D"),
    SHA224_With_RSA("2A 86 48 86 F7 0D 01 01 0E"),

    EmailAddress("2A 86 48 86 F7 0D 01 09 01"),

    MD5("2A 86 48 86 F7 0D 02 05"),
    HMAC_With_SHA1("2A 86 48 86 F7 0D 02 07"),
    HMAC_With_SHA224("2A 86 48 86 F7 0D 02 08"),
    HMAC_With_SHA256("2A 86 48 86 F7 0D 02 09"),
    HMAC_With_SHA384("2A 86 48 86 F7 0D 02 0A"),
    HMAC_With_SHA512("2A 86 48 86 F7 0D 02 0B"),

    DSA("2A 86 48 CE 38 04 01"),
    SHA1_WITH_DSA("2A 86 48 CE 38 04 03"),

    EC_Public_Key("2A 86 48 CE 3D 02 01"),

    prime192v1("2A 86 48 CE 3D 03 01 01"),
    prime192v2("2A 86 48 CE 3D 03 01 02"),
    prime192v3("2A 86 48 CE 3D 03 01 03"),
    prime239v1("2A 86 48 CE 3D 03 01 04"),
    prime239v2("2A 86 48 CE 3D 03 01 05"),
    prime239v3("2A 86 48 CE 3D 03 01 06"),
    prime256v1("2A 86 48 CE 3D 03 01 07"),

    SHA224_WITH_ECDSA("2A 86 48 CE 3D 04 03 01"),
    SHA256_WITH_ECDSA("2A 86 48 CE 3D 04 03 02"),
    SHA384_WITH_ECDSA("2A 86 48 CE 3D 04 03 03"),
    SHA512_WITH_ECDSA("2A 86 48 CE 3D 04 03 04"),

    DH("2A 86 48 CE 3E 02 01"),

    ExtendedValidationCertificates("2B 06 01 04 01 D6 79 02 04 02"),
    AuthorityInfoAccess("2B 06 01 05 05 07 01 01"),

    ServerAuth("2B 06 01 05 05 07 03 01"),
    ClientAuth("2B 06 01 05 05 07 03 02"),
    CodeSigning("2B 06 01 05 05 07 03 03"),
    EmailProtection("2B 06 01 05 05 07 03 04"),
    IpsecEndSystem("2B 06 01 05 05 07 03 05"),
    IpsecTunnel("2B 06 01 05 05 07 03 06"),
    IpsecUser("2B 06 01 05 05 07 03 07"),
    TimeStamping("2B 06 01 05 05 07 03 08"),
    OCSPSigning("2B 06 01 05 05 07 03 09"),

//    DSA("2B 0E 03 02 0C"),
    SHA("2B 0E 03 02 12"),


    CommonName("55 04 03"),
    Surname("55 04 04"),
    SerialNumber("55 04 05"),
    CountryName("55 04 06"),
    LocalityName("55 04 07"),
    StateOrProvinceName("55 04 08"),
    StreetAddress("55 04 09"),
    OrganizationName("55 04 0A"),
    OrganizationalUnitName("55 04 0B"),

    SubjectKeyIdentifier("55 1D 0E"),
    KeyUsage("55 1D 0F"),
    PrivateKeyUsagePeriod("55 1D 10"),
    SubjectAltName("55 1D 11"),
    IssuerAltName("55 1D 12"),
    BasicConstraints("55 1D 13"),
    CRLNumber("55 1D 14"),
    CRLDistributionPoints("55 1D 1F"),
    CertificatePolicies("55 1D 20"),
    AuthorityKeyIdentifier("55 1D 23"),
    ExtKeyUsage("55 1D 25"),


    SHA256("60 86 48 01 65 03 04 02 01"),
    SHA384("60 86 48 01 65 03 04 02 02"),
    SHA512("60 86 48 01 65 03 04 02 03"),
    SHA224("60 86 48 01 65 03 04 02 04"),

    SHA224_WITH_DSA("60 86 48 01 65 03 04 03 01"),
    SHA256_WITH_DSA("60 86 48 01 65 03 04 03 02"),
    ;

    
    public final byte[] bytes;

    ObjectIdentifier(String hex_str) {
        this.bytes = HexUtils.parse(hex_str, HexFormat.FORMAT_FF_SPACE_FF);
    }

    public boolean equals(byte[] bytes) {
        return Arrays.equals(this.bytes, bytes);
    }

    public String toDecimalString() {
        return OIDUtils.format(bytes);
    }

    public static ObjectIdentifier valueOf(byte[] data) {
        Optional<ObjectIdentifier> result = Arrays.stream(values()).filter(item -> Arrays.equals(item.bytes, data)).findFirst();
        if (result.isPresent()) {
            return result.get();
        }
        else {
            throw new RuntimeException("Unknown OID: " + HexUtils.format(data, HexFormat.FORMAT_FF_SPACE_FF));
        }
    }
}
