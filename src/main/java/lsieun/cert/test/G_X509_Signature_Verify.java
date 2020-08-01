package lsieun.cert.test;

import lsieun.cert.asn1.PEMUtils;
import lsieun.cert.rsa.RSAPublicKey;
import lsieun.cert.x509.X509Utils;
import lsieun.utils.ByteUtils;
import lsieun.utils.FileUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.math.BigInteger;

@SuppressWarnings("Duplicates")
public class G_X509_Signature_Verify {
    public static void main(String[] args) {
        String modulus_str =
                "00:f0:53:13:dc:be:0b:64:64:2c:58:02:7b:3b:52:" +
                        "b1:4b:2c:d0:80:b3:d9:25:38:db:32:09:1f:f8:92:" +
                        "ba:f4:66:a1:67:5a:84:62:99:56:f7:4c:fd:0c:45:" +
                        "3f:86:61:88:17:51:70:70:ff:4f:be:07:15:27:8d:" +
                        "88:42:45:29:27:c1:93:28:aa:11:51:ef:a7:11:22:" +
                        "db:a2:08:08:65:ed:50:52:45:46:0c:5b:f7:80:09:" +
                        "e4:41:0a:76:5d:be:e3:bd:cd:73:4f:20:62:21:8d:" +
                        "37:86:81:65:38:2a:21:e6:8b:0b:97:c0:2e:36:1f:" +
                        "e5:51:e8:9b:94:08:9f:12:d1:be:a0:2d:66:1e:30:" +
                        "b2:fc:cf:6b:d2:98:07:b1:0f:ed:66:67:40:b5:87:" +
                        "4c:c9:b7:55:32:7e:ef:35:79:51:83:13:98:f8:90:" +
                        "29:6d:41:81:12:a5:d7:73:d4:7e:ee:73:fe:4f:c7:" +
                        "fb:80:99:3a:2b:12:1f:80:0a:2a:99:8e:87:48:b5:" +
                        "72:8f:54:8f:60:ab:69:05:39:fd:3c:08:f4:4e:9d:" +
                        "99:bc:64:cb:85:88:e2:d8:84:2c:a1:c4:6a:f6:c3:" +
                        "d3:57:fa:2c:ee:14:9d:02:63:32:ae:15:1c:90:b6:" +
                        "1d:5e:e4:d4:68:49:1e:60:21:eb:b3:f9:f3:b8:7c:" +
                        "b7:89";
        byte[] modulus_bytes = HexUtils.parse(modulus_str, HexFormat.FORMAT_FF_COLON_FF);
        BigInteger modulus = new BigInteger(1, modulus_bytes);
        BigInteger exponent = new BigInteger("65537");
        RSAPublicKey rsaKey = new RSAPublicKey(modulus, exponent);

        String filepath = FileUtils.getFilePath("cert/rsa/signed_certificate.pem");
        byte[] bytes = PEMUtils.read(filepath);

        boolean flag = X509Utils.validate_certificate_rsa(bytes, rsaKey);
        System.out.println(flag);
    }
}
