package lsieun.crypto.sym.sample;

import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

public class AES128Sample {
    public static String key = "2B7E1516 28AED2A6 ABF71588 09CF4F3C".replaceAll(" ", "");
    public static byte[] key_bytes = HexUtils.parse(key, HexFormat.FORMAT_FF_FF);

    public static String iv = "00010203 04050607 08090A0B 0C0D0E0F".replaceAll(" ", "");
    public static byte[] iv_bytes = HexUtils.parse(iv, HexFormat.FORMAT_FF_FF);

    public static String plain_text = (
            "6BC1BEE2 2E409F96 E93D7E11 7393172A" +
                    "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51" +
                    "30C81C46 A35CE411 E5FBC119 1A0A52EF" +
                    "F69F2445 DF4F9B17 AD2B417B E66C3710").replaceAll(" ", "");
    public static byte[] plain_text_bytes = HexUtils.parse(plain_text, HexFormat.FORMAT_FF_FF);

    public static String cfb_cipher_text = (
            "3B3FD92E B72DAD20 333449F8 E83CFB4A" +
                    "C8A64537 A0B3A93F CDE3CDAD 9F1CE58B" +
                    "26751F67 A3CBB140 B1808CF1 87A4F4DF" +
                    "C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6"
    ).replaceAll(" ", "");
    public static byte[] cfb_cipher_text_bytes = HexUtils.parse(cfb_cipher_text, HexFormat.FORMAT_FF_FF);

    public static String ofb_cipher_text = (
            "3B3FD92E B72DAD20 333449F8 E83CFB4A" +
                    "7789508D 16918F03 F53C52DA C54ED825" +
                    "9740051E 9C5FECF6 4344F7A8 2260EDCC" +
                    "304C6528 F659C778 66A510D9 C1D6AE5E"
    ).replaceAll(" ", "");
    public static byte[] ofb_cipher_text_bytes = HexUtils.parse(ofb_cipher_text, HexFormat.FORMAT_FF_FF);

    public static String nonce = "F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF".replaceAll(" ", "");
    public static byte[] nonce_bytes = HexUtils.parse(nonce, HexFormat.FORMAT_FF_FF);

    public static String ctr_cipher_text = (
            "874D6191 B620E326 1BEF6864 990DB6CE" +
                    "9806F66B 7970FDFF 8617187B B9FFFDFF" +
                    "5AE4DF3E DBD5D35E 5B4F0902 0DB03EAB" +
                    "1E031DDA 2FBE03D1 792170A0 F3009CEE"
    ).replaceAll(" ", "");
    public static byte[] ctr_cipher_text_bytes = HexUtils.parse(ctr_cipher_text, HexFormat.FORMAT_FF_FF);

}

/*

 */
