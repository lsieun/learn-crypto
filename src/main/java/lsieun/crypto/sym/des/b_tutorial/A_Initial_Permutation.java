package lsieun.crypto.sym.des.b_tutorial;

import lsieun.crypto.sym.des.DESConst;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

public class A_Initial_Permutation {
    public static void main(String[] args) {
        byte[] msg_64_bit_bytes = {'c', 'a', 'f', 'e', 'b', 'a', 'b', 'e'};
        byte[] permuted_msg_64_bit_bytes = DESUtils.permute(msg_64_bit_bytes, DESConst.ip_table);

        System.out.println(ByteUtils.toBinary(msg_64_bit_bytes));
        System.out.println(ByteUtils.toBinary(permuted_msg_64_bit_bytes));
    }
}
