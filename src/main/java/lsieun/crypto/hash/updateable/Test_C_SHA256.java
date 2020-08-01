package lsieun.crypto.hash.updateable;

import lsieun.utils.HexUtils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Test_C_SHA256 {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Downloads/texlive2019-20190410.iso";
        try (
                InputStream in = new FileInputStream(filepath);
                BufferedInputStream bin = new BufferedInputStream(in);
        ) {

            byte[] buff = new byte[1024 * 1024];
            int length;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            DigestCtx ctx = DigestCtx.new_sha256_digest();
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
