package lsieun.crypto.sym.des.d_test;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.HexUtils;

import java.util.Arrays;
import java.util.Random;

public class FeistelFunction {
    public static byte[] feistel(byte[] input_bytes, byte[] current_48_bit_sub_key_bytes) {
        byte[] content_64_bit_bytes = Arrays.copyOfRange(input_bytes, 0, 8);

        // msg
        byte[] left_32_bit_bytes = Arrays.copyOfRange(content_64_bit_bytes, 0, 4);
        byte[] right_32_bit_bytes = Arrays.copyOfRange(content_64_bit_bytes, 4, 8);

        byte[] expansion_48_bit_bytes = DESUtils.permute(right_32_bit_bytes, DESConst.expansion_table);
        byte[] xor_48_bit_bytes = DESUtils.xor(expansion_48_bit_bytes, current_48_bit_sub_key_bytes, 6);
        byte[] substitution_32_bit_bytes = DESUtils.get_substitution(xor_48_bit_bytes);
        byte[] permutation_32_bit_bytes = DESUtils.permute(substitution_32_bit_bytes, DESConst.p_table);
        byte[] xor_32_bit_bytes = DESUtils.xor(permutation_32_bit_bytes, left_32_bit_bytes, 4);

        // copy 注意：这里与DES不同，没有交换位置。
        System.arraycopy(xor_32_bit_bytes, 0, content_64_bit_bytes, 0, 4);
        System.arraycopy(right_32_bit_bytes, 0, content_64_bit_bytes, 4, 4);

        return content_64_bit_bytes;
    }

    public static byte[] getRandomBytes(int length) {
        Random rand = new Random(System.currentTimeMillis());

        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) rand.nextInt();
        }
        return bytes;
    }

    public static void main(String[] args) {
        byte[] input_64_bit_bytes = getRandomBytes(8);
        byte[] sub_key_48_bit_bytes = getRandomBytes(6);

        byte[] encrypted_bytes = feistel(input_64_bit_bytes, sub_key_48_bit_bytes);
        byte[] decrypted_bytes = feistel(encrypted_bytes, sub_key_48_bit_bytes);

        System.out.println(" Original: " + HexUtils.toHex(input_64_bit_bytes));
        System.out.println("Encrypted: " + HexUtils.toHex(encrypted_bytes));
        System.out.println("Decrypted: " + HexUtils.toHex(decrypted_bytes));
        System.out.println("   Equals: " + Arrays.equals(input_64_bit_bytes, decrypted_bytes));
    }


}
