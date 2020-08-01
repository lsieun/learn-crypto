package lsieun.crypto.hash.hmac.b_test;

import lsieun.crypto.hash.hmac.HMACUtils;
import lsieun.crypto.hash.hmac.MACSample;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.HexUtils;

public class C_Self_HMAC_SHA256 {
    public static void main(String[] args) {
        byte[] mac_bytes = HMACUtils.hmac(MACSample.key_bytes, MACSample.data, SHA256Utils::sha256_hash);
        System.out.println(HexUtils.toHex(mac_bytes));
    }
}
