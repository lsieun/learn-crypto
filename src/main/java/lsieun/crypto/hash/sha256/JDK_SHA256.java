package lsieun.crypto.hash.sha256;

import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JDK_SHA256 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] bytes = SHA256Example.example_2.getBytes(StandardCharsets.UTF_8);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes);
        byte[] digest = md.digest();
        System.out.println(HexUtils.toHex(digest));
    }
}
