package lsieun.crypto.hash.hmac.b_test;

import lsieun.crypto.hash.hmac.HMACUtils;
import lsieun.crypto.hash.hmac.MACSample;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.utils.HexUtils;

public class B_Self_HMAC_SHA1 {
    public static void main(String[] args) {
        byte[] mac_bytes = HMACUtils.hmac(MACSample.key_bytes, MACSample.data, SHA1Utils::sha1_hash);
        System.out.println(HexUtils.toHex(mac_bytes));
    }
}
