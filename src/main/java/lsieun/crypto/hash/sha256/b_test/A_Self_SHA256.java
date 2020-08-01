package lsieun.crypto.hash.sha256.b_test;

import lsieun.crypto.hash.sha256.SHA256Example;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;

public class A_Self_SHA256 {
    public static void main(String[] args) {
        byte[] bytes = SHA256Example.example_1.getBytes(StandardCharsets.UTF_8);

        byte[] digest = SHA256Utils.sha256_hash(bytes);
        System.out.println(HexUtils.toHex(digest));
    }
}
