package lsieun.crypto.sym.des.a_basic;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

// 这里说明一个很重要的问题：ip_table和fp_table是逆向操作
@SuppressWarnings("Duplicates")
public class Permutation_Reverse {
    public static void main(String[] args) {
        byte[] content_64_bit_bytes = {'c', 'a', 'f', 'e', 'b', 'a', 'b', 'e'};
        byte[] initial_permutation_bytes = DESUtils.permute(content_64_bit_bytes, DESConst.ip_table);
        byte[] final_permutation_bytes = DESUtils.permute(initial_permutation_bytes, DESConst.fp_table);

        // to binary
        System.out.println(ByteUtils.toBinary(content_64_bit_bytes));
        System.out.println(ByteUtils.toBinary(final_permutation_bytes));

        // to int
        System.out.println(Arrays.toString(content_64_bit_bytes));
        System.out.println(Arrays.toString(final_permutation_bytes));
    }
}
