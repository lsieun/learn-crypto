package lsieun.crypto.hash.updateable;

import lsieun.utils.HexUtils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Test_A_MD5 {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Downloads/ideaIU-2020.1.4.tar.gz";
        try (
                InputStream in = new FileInputStream(filepath);
                BufferedInputStream bin = new BufferedInputStream(in);
        ) {

            byte[] buff = new byte[1024 * 1024];
            int length;

            MessageDigest md = MessageDigest.getInstance("MD5");
            DigestCtx ctx = DigestCtx.new_md5_digest();
            while ((length = bin.read(buff)) != -1) {
                ByteArrayOutputStream bao = new ByteArrayOutputStream();
                bao.write(buff, 0, length);
                byte[] bytes = bao.toByteArray();
                md.update(bytes);
                Digest.update_digest(ctx, bytes);
            }

            byte[] digest1 = Digest.finalize_digest(ctx);
            System.out.println(HexUtils.toHex(digest1));
            byte[] digest2 = md.digest();
            System.out.println(HexUtils.toHex(digest2));

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


}
