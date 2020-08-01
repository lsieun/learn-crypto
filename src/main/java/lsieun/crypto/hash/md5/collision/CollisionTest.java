package lsieun.crypto.hash.md5.collision;

import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CollisionTest {
    // 79054025255fb1a26e4bc422aef54eb4
    public static final String collision_str_1 =
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89" +
                    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b" +
                    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0" +
                    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";

    // 79054025255fb1a26e4bc422aef54eb4
    public static final String collision_str_2 =
            "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89" +
                    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b" +
                    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0" +
                    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String str1 = collision_str_1;
        String str2 = collision_str_2;

        System.out.println("str equals: " + str1.equals(str2));

        String str1_md5 = getMD5(str1);
        String str2_md5 = getMD5(str2);
        System.out.println("md5 equals: " + str1_md5.equals(str2_md5));
        System.out.println(str1_md5);
        System.out.println(str2_md5);
    }

    public static String getMD5(String hex_str) throws NoSuchAlgorithmException {
        byte[] bytes = HexUtils.parse(hex_str, HexFormat.FORMAT_FF_FF);

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(bytes);
        byte[] digest = md.digest();
        return HexUtils.toHex(digest);
    }
}
