package lsieun.tls.cipher;

public enum SignatureAlgorithm {
    UNDEFINED("undefined", -1),
    ANONYMOUS("anonymous", 0),
    RSA("rsa", 1),
    DSA("dsa", 2),
    ECDSA("ecdsa", 3);

    public final String name;
    public final int value;

    SignatureAlgorithm(String name, int value) {
        this.name = name;
        this.value = value;
    }

    public static SignatureAlgorithm valueOf(int value) {
        SignatureAlgorithm item = UNDEFINED;
        switch (value) {
            case 0:
                item = ANONYMOUS;
                break;
            case 1:
                item = RSA;
                break;
            case 2:
                item = DSA;
                break;
            case 3:
                item = ECDSA;
                break;
        }
        return item;
    }
}
