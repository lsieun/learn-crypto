package lsieun.tls.cipher;

public enum HashAlgorithm {
    UNDEFINED("undefined", "", -1, -1),
    NONE("none", "NONE", 0, -1),
    MD5("md5", "MD5", 1, 16),
    SHA1("sha1", "SHA-1", 2, 20),
    SHA224("sha224", "SHA-224", 3, 28),
    SHA256("sha256", "SHA-256", 4, 32),
    SHA384("sha384", "SHA-384", 5, 48),
    SHA512("sha512", "SHA-512", 6, 64);

    public final String name;
    public final String standardName;
    public final int value;
    public final int length;

    HashAlgorithm(String name, String standardName, int value, int length) {
        this.name = name;
        this.standardName = standardName;
        this.value = value;
        this.length = length;
    }

    public static HashAlgorithm valueOf(int value) {
        HashAlgorithm item = UNDEFINED;
        switch(value) {
            case 0:
                item = NONE;
                break;
            case 1:
                item = MD5;
                break;
            case 2:
                item = SHA1;
                break;
            case 3:
                item = SHA224;
                break;
            case 4:
                item = SHA256;
                break;
            case 5:
                item = SHA384;
                break;
            case 6:
                item = SHA512;
                break;
        }

        return item;
    }
}
