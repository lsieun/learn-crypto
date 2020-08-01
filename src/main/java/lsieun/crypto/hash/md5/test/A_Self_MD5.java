package lsieun.crypto.hash.md5.test;

import lsieun.crypto.hash.md5.MD5Example;
import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.utils.HexUtils;

public class A_Self_MD5 {

    public static void main(String[] args) {
        byte[] bytes = MD5Example.input_52_bytes;

        byte[] digest_bytes = MD5Utils.md5_hash(bytes);
        String md5 = HexUtils.toHex(digest_bytes);
        System.out.println(md5);
    }
}
