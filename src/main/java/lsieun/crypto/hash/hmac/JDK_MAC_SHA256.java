package lsieun.crypto.hash.hmac;

import lsieun.utils.HexUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JDK_MAC_SHA256 {
    public static void main(String[] args) throws Exception {
        byte[] key_bytes = MACSample.key_bytes;
        byte[] input = MACSample.data;
        byte[] mac_bytes = mac_sha256(key_bytes, input);
        System.out.println(HexUtils.toHex(mac_bytes));
    }

    public static byte[] mac_sha256(byte[] key_bytes, byte[] input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");

        String algorithm = "RawBytes";
        SecretKeySpec key = new SecretKeySpec(key_bytes, algorithm);
        mac.init(key);

        byte[] mac_bytes = mac.doFinal(input);
        return mac_bytes;
    }
}
