package lsieun.crypto.sym.aes.b_tutorial;

import lsieun.utils.ByteUtils;
import lsieun.utils.PrintUtils;

import java.util.List;

public class A_Key_Schedule_01_XOR {
    private static final int WORD_SIZE = 4;

    public static void main(String[] args) {
        // 第一步，准备一个16 byte的数组
        byte[] key_bytes = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'};

        // 第二步，将数组按4 byte为一组划分后，添加到list当中
        List<byte[]> list = ByteUtils.toList(key_bytes, WORD_SIZE);

        // 第三步，进行XOR操作
        apply(list, 20);

        // 第四步，打印结果
        PrintUtils.display_hex(list);
    }

    public static void apply(List<byte[]> list, int count) {
        for (int i = 0; i < count; i++) {
            int size = list.size();
            byte[] bytes1 = list.get(size - WORD_SIZE);
            byte[] bytes2 = list.get(size - 1);
            byte[] bytes = ByteUtils.xor(bytes1, bytes2, WORD_SIZE);
            list.add(bytes);
        }
    }

}
