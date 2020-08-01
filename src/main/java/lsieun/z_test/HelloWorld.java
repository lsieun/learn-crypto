package lsieun.z_test;

import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class HelloWorld {
    public static void main(String[] args) throws Exception {
//        System.setProperty("javax.net.debug", "ssl:record");
//        URL url = new URL("https://www.baidu.com");
//        final URLConnection conn = url.openConnection();
//        final InputStream in = conn.getInputStream();
//        int b;
//        while ((b = in.read()) != -1) {
//            System.out.print((char) b);
//        }
        String str = "117, 163, 206, 248, 138, 162, 131, 187, 7, 136, 203, 55, 54, 50, 12, 101, 245, 144, 58, 224, 62, 235, 204, 60, 169, 215, 200, 160, 128, 46, 124, 9, 113, 172, 247, 40, 152, 42, 201, 255, 253, 160, 190, 175, 112, 119, 167, 221, 186, 60, 30, 33, 253, 107, 82, 43, 186, 242, 19, 113, 140, 34, 196, 167, 13, 174, 203, 27, 168, 103, 14, 107, 24, 26, 237, 177, 147, 126, 86, 37, 159, 157, 248, 210, 157, 19, 74, 52, 186, 37, 221, 218, 197, 213, 184, 45, 210, 149, 43, 67, 103, 141, 16, 252, 250, 71, 246, 150, 248, 46, 254, 204, 165, 238, 83, 0, 220, 94, 255, 119, 68, 22, 12, 241, 144, 229, 83, 103";
        String[] array = str.split(",");
        byte[] bytes = new byte[array.length];
        for (int i=0;i<array.length;i++) {
            bytes[i] = (byte)Integer.parseInt(array[i].trim());
        }
        String hex = HexUtils.format(bytes, " ", 16);
        System.out.println(hex);
    }
}
