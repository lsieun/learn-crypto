package lsieun.crypto.hash.md5.test;

import lsieun.crypto.hash.md5.MD5Example;
import lsieun.utils.HexUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class C_JDK_MD5 {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] bytes = MD5Example.input_52_bytes;

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(bytes);
        byte[] digest = md.digest();
        System.out.println(HexUtils.toHex(digest));
    }
}
