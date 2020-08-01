package lsieun.crypto.hash.hmac.b_test;

import lsieun.crypto.hash.hmac.HMACUtils;
import lsieun.crypto.hash.hmac.JDK_MAC_SHA256;
import lsieun.crypto.hash.hmac.MACSample;
import lsieun.crypto.hash.sha256.SHA256Utils;

import java.util.Arrays;
import java.util.Random;

public class D_HMAC_SHA256 {
    public static void main(String[] args) throws Exception {
        int key_size = 200;
        byte[] key_bytes = new byte[key_size];
        Random rand = new Random(System.currentTimeMillis());
        for (int i=0;i<key_size;i++) {
            key_bytes[i] = (byte) rand.nextInt();
        }

        byte[] input = MACSample.data;

        byte[] hmac_bytes = HMACUtils.hmac(key_bytes, input, SHA256Utils::sha256_hash);
        byte[] mac_bytes = JDK_MAC_SHA256.mac_sha256(key_bytes, input);
        System.out.println(Arrays.equals(hmac_bytes, mac_bytes));
    }
}
