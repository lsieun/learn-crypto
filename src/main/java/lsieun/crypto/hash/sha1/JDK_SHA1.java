package lsieun.crypto.hash.sha1;

import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JDK_SHA1 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] bytes = SHA1Example.example_1.getBytes(StandardCharsets.UTF_8);

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(bytes);
        byte[] digest = md.digest();
        System.out.println(HexUtils.toHex(digest));
    }
}
