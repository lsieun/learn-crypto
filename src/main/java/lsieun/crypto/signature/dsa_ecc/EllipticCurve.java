package lsieun.crypto.signature.dsa_ecc;

import lsieun.crypto.asym.ecc.Point;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

public class EllipticCurve {
    public static final EllipticCurve P256 = new EllipticCurve(
            new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
            new BigInteger("-3"),
            new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"),
            new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
            new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"),
            new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
            new BigInteger("1")
    );

    public static void main(String[] args) {
        String hex_str = ("0118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449" +
                "579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901" +
                "3fad0761 353c7086 a272c240 88be9476 9fd16650").replaceAll(" ", "");
        byte[] bytes = HexUtils.parse(hex_str, HexFormat.FORMAT_FF_FF);
        System.out.println(HexUtils.toHex(bytes));
        BigInteger value = new BigInteger(1, bytes);
        System.out.println(value.bitLength());
        System.out.println(value);
        System.out.println(P256.p.bitLength());
    }

    public final BigInteger p;
    public final BigInteger a;
    public final BigInteger b;
    public final Point G;
    public final BigInteger n;
    public final BigInteger h;

    public EllipticCurve(BigInteger p, BigInteger a, BigInteger b, Point g, BigInteger n, BigInteger h) {
        this.p = p;
        this.a = a;
        this.b = b;
        this.G = g;
        this.n = n;
        this.h = h;
    }

    public EllipticCurve(BigInteger p, BigInteger a, BigInteger b, BigInteger x, BigInteger y, BigInteger n, BigInteger h) {
        this.p = p;
        this.a = a;
        this.b = b;
        this.G = new Point(x, y);
        this.n = n;
        this.h = h;
    }
}
