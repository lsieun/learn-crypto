package lsieun.cert.test;

import lsieun.utils.FileUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

public class A_DER_HEX {
    public static void main(String[] args) {
        String filepath = "/home/liusen/Workspace/tmp/cert.der";
        byte[] bytes = FileUtils.readBytes(filepath);
        String result = HexUtils.format(bytes, HexFormat.FORMAT_FF_SPACE_FF_16);
        System.out.println(result);
    }
}
