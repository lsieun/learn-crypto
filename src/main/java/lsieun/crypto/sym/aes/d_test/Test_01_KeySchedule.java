package lsieun.crypto.sym.aes.d_test;

import lsieun.crypto.sym.aes.AESAlgorithm;
import lsieun.crypto.sym.aes.AESUtils;
import lsieun.utils.ByteUtils;

import java.util.Arrays;
import java.util.List;

public class Test_01_KeySchedule {
    public static void main(String[] args) {
        int key_bit_size = AESAlgorithm.KEY_SIZE_128;
        int key_byte_size = key_bit_size / 8;

        AESAlgorithm alg = new AESAlgorithm(key_bit_size);
        byte[] key_bytes = alg.createKey();

        // first method
        int[] word_key_expansion = alg.createKeyExpansion(key_bytes);

        // second method
        List<byte[]> bytes_list = AESUtils.compute_key_schedule(key_bytes);

        // display
        System.out.println(word_key_expansion.length);
        for (int i = 0; i < word_key_expansion.length; i++) {
            int value = word_key_expansion[i];
            byte[] bytes1 = ByteUtils.toBytes(value);
            String line = String.format("%02d: %s", (i + 1), ByteUtils.toBinary(bytes1));
            System.out.println(line);

            byte[] bytes2 = bytes_list.get(i);
            String line2 = String.format("%02d: %s", (i + 1), ByteUtils.toBinary(bytes2));
            System.out.println(line2);

            System.out.println(Arrays.equals(bytes1, bytes2));
        }
    }
}
