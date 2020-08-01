package lsieun.cert.asn1;

public class ASN1Const {
    public static final int ASN1_CLASS_UNIVERSAL = 0;
    public static final int ASN1_CLASS_APPLICATION = 1;
    public static final int ASN1_CONTEXT_SPECIFIC = 2;
    public static final int ASN1_PRIVATE = 3;

    public static final int ASN1_BER = 0;
    public static final int ASN1_BOOLEAN = 1;
    public static final int ASN1_INTEGER = 2;
    public static final int ASN1_BIT_STRING = 3;
    public static final int ASN1_OCTET_STRING = 4;
    public static final int ASN1_NULL = 5;
    public static final int ASN1_OBJECT_IDENTIFIER = 6;
    public static final int ASN1_OBJECT_DESCRIPTOR = 7;
    public static final int ASN1_INSTANCE_OF_EXTERNAL = 8;
    public static final int ASN1_REAL = 9;
    public static final int ASN1_ENUMERATED = 10;
    public static final int ASN1_EMBEDDED_PPV = 11;
    public static final int ASN1_UTF8_STRING = 12;
    public static final int ASN1_RELATIVE_OID = 13;
    // 14 & 15 undefined
    public static final int ASN1_SEQUENCE = 16;
    public static final int ASN1_SET = 17;
    public static final int ASN1_NUMERIC_STRING = 18;
    public static final int ASN1_PRINTABLE_STRING = 19;
    public static final int ASN1_TELETEX_STRING = 20;
    public static final int ASN1_T61_STRING = 20;
    public static final int ASN1_VIDEOTEX_STRING = 21;
    public static final int ASN1_IA5_STRING = 22;
    public static final int ASN1_UTC_TIME = 23;
    public static final int ASN1_GENERALIZED_TIME = 24;
    public static final int ASN1_GRAPHIC_STRING = 25;
    public static final int ASN1_VISIBLE_STRING = 26;
    public static final int ASN1_ISO64_STRING = 26;
    public static final int ASN1_GENERAL_STRING = 27;
    public static final int ASN1_UNIVERSAL_STRING = 28;
    public static final int ASN1_CHARACTER_STRING = 29;
    public static final int ASN1_BMP_STRING = 30;

    public static String[] tag_names = {
            "BER",//0
            "BOOLEAN",//1
            "INTEGER",//2
            "BIT STRING",//3
            "OCTET STRING",//4
            "NULL",//5
            "OBJECT IDENTIFIER",//6
            "ObjectDescriptor",//7
            "INSTANCE OF, EXTERNAL",//8
            "REAL",//9
            "ENUMERATED",//10
            "EMBEDDED PPV",//11
            "UTF8String",//12
            "RELATIVE-OID",//13
            "undefined(14)",//14
            "undefined(15)",//15
            "SEQUENCE, SEQUENCE OF",//16
            "SET, SET OF",//17
            "NumericString",//18
            "PrintableString",//19
            "TeletexString, T61String",//20
            "VideotexString",//21
            "IA5String",//22
            "UTCTime",//23
            "GeneralizedTime",//24
            "GraphicString",//25
            "VisibleString, ISO64String",//26
            "GeneralString",//27
            "UniversalString",//28
            "CHARACTER STRING",//29
            "BMPString"//30
    };
}
