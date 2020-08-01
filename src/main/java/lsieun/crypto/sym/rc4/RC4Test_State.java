package lsieun.crypto.sym.rc4;

import lsieun.utils.ByteUtils;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;

public class RC4Test_State {
    public static void main(String[] args) {
        byte[] plain_text = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
        byte[] key = "abcdef".getBytes(StandardCharsets.UTF_8);

        RC4State state = new RC4State();
        byte[] output1 = RC4Utils.rc4_operate(plain_text, key, state);
        System.out.println(HexUtils.toHex(output1));

        byte[] output2 = RC4Utils.rc4_operate(plain_text, key, state);
        System.out.println(HexUtils.toHex(output2));
    }
}
