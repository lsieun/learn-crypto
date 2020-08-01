package lsieun.cert.x509;

import lsieun.cert.asn1.ASN1Struct;
import lsieun.cert.cst.ObjectIdentifier;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class Name {
    public final String CountryName;
    public final String StateOrProvinceName;
    public final String LocalityName;
    public final String OrganizationName;
    public final String OrganizationUnitName;
    public final String CommonName;
    public final String EmailAddress;

    public Name(String countryName,
                String stateOrProvinceName,
                String localityName,
                String organizationName,
                String organizationUnitName,
                String commonName,
                String emailAddress) {
        this.CountryName = countryName;
        this.StateOrProvinceName = stateOrProvinceName;
        this.LocalityName = localityName;
        this.OrganizationName = organizationName;
        this.OrganizationUnitName = organizationUnitName;
        this.CommonName = commonName;
        this.EmailAddress = emailAddress;
    }

    @Override
    public String toString() {
        return "Name{" +
                "CountryName='" + CountryName + "'" +
                ", StateOrProvinceName='" + StateOrProvinceName + "'" +
                ", LocalityName='" + LocalityName + "'" +
                ", OrganizationName='" + OrganizationName + "'" +
                ", OrganizationUnitName='" + OrganizationUnitName + "'" +
                ", CommonName='" + CommonName + "'" +
                ", emailAddress='" + EmailAddress + "'" +
                '}';
    }

    public static Name parse(ASN1Struct struct) {
        StringBuilder countryName = new StringBuilder();
        StringBuilder stateOrProvinceName = new StringBuilder();
        StringBuilder localityName = new StringBuilder();
        StringBuilder organizationName = new StringBuilder();
        StringBuilder organizationUnitName = new StringBuilder();
        StringBuilder commonName = new StringBuilder();
        StringBuilder emailAddress = new StringBuilder();


        List<ASN1Struct> children = struct.children;
        for (ASN1Struct item : children) {
            byte[] oid_bytes = item.children.get(0).children.get(0).data;
            byte[] content_bytes = item.children.get(0).children.get(1).data;
            String content = new String(content_bytes, StandardCharsets.UTF_8);

            ObjectIdentifier oid = ObjectIdentifier.valueOf(oid_bytes);
            switch (oid) {
                case CommonName:
                    commonName.append(content);
                    break;
                case CountryName:
                    countryName.append(content);
                    break;
                case LocalityName:
                    localityName.append(content);
                    break;
                case StateOrProvinceName:
                    stateOrProvinceName.append(content);
                    break;
                case OrganizationalUnitName:
                    organizationUnitName.append(content);
                    break;
                case OrganizationName:
                    organizationName.append(content);
                    break;
                case EmailAddress:
                    emailAddress.append(content);
                    break;
                default:
                    System.out.println("Unsupported OID: " + oid);
                    break;
            }
        }

        return new Name(countryName.toString(),
                stateOrProvinceName.toString(),
                localityName.toString(),
                organizationName.toString(),
                organizationUnitName.toString(),
                commonName.toString(),
                emailAddress.toString());
    }
}
