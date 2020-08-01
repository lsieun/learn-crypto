package lsieun.tls.test;

import lsieun.crypto.hash.hmac.HMACUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

public class P_MD5_HMAC_Test {
    public static void main(String[] args) {
        byte[] secret = new byte[]{'a', 'b'};
        byte[] seed = new byte[]{'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'};

        byte[] A1 = HMACUtils.hmac_md5(secret, seed);
        System.out.println("A1: " + HexUtils.format(A1, HexFormat.FORMAT_FF_SPACE_FF));

        byte[] A2 = HMACUtils.hmac_md5(secret, A1);
        System.out.println("A2: " + HexUtils.format(A2, HexFormat.FORMAT_FF_SPACE_FF));

        byte[] A3 = HMACUtils.hmac_md5(secret, A2);
        System.out.println("A3: " + HexUtils.format(A3, HexFormat.FORMAT_FF_SPACE_FF));

        byte[] result_part_1 = HMACUtils.hmac_md5(secret, ByteUtils.concatenate(A1, seed));
        System.out.println("result_part_1: " + HexUtils.format(result_part_1, HexFormat.FORMAT_FF_SPACE_FF));

        byte[] result_part_2 = HMACUtils.hmac_md5(secret, ByteUtils.concatenate(A2, seed));
        System.out.println("result_part_2: " + HexUtils.format(result_part_2, HexFormat.FORMAT_FF_SPACE_FF));

        byte[] result_part_3 = HMACUtils.hmac_md5(secret, ByteUtils.concatenate(A3, seed));
        System.out.println("result_part_3: " + HexUtils.format(result_part_3, HexFormat.FORMAT_FF_SPACE_FF));
    }
}
