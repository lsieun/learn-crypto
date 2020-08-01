package lsieun.crypto.hash.hmac;

import lsieun.utils.HexUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JDK_MAC_MD5 {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacMD5");

        String algorithm  = "RawBytes";
        SecretKeySpec key = new SecretKeySpec(MACSample.key_bytes, algorithm);
        mac.init(key);

        byte[] mac_bytes = mac.doFinal(MACSample.data);
        System.out.println(HexUtils.toHex(mac_bytes));
    }
}
