package lsieun.crypto.sym.aes.a_basic;

import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.ByteUtils;
import lsieun.utils.HexUtils;

/**
 * <p>我们说，存在性，即存在“这样的机制”：一个数，经过“这个机制”的多次运算，就会产生出有规律的、重复的结果。</p>
 *
 * <p>xtime这个方法，它让我认知到了一件事情：可以通过人为的构造一种运算机制，让它产生出具有循环规律的结果。</p>
 *
 * <p>像直接位移（shift）、异或（xor）是非常明显的具有循环规律的结果，而像xtime却是经过人工构造出来的。</p>
 */
public class A_03_XTime_Loop {
    private static final String FORMAT = "%03d: %s %s";

    public static void main(String[] args) {
        int count = 105;
        byte x = 0x01;
//        {
//            Random rand = new Random();
//            x = (byte) rand.nextInt();
//        }

        String first_line = String.format(FORMAT, 0, ByteUtils.toBinary(x), HexUtils.toHex(new byte[]{x}));
        System.out.println(first_line);

        for (int i = 0; i < count; i++) {
            x = AESUtils.xtime(x);
            String line = String.format(FORMAT, (i+1), ByteUtils.toBinary(x), HexUtils.toHex(new byte[]{x}));
            System.out.println(line);
        }
    }
}
