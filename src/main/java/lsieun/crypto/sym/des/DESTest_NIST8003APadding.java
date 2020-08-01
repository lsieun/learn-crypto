package lsieun.crypto.sym.des;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.PaddingUtils;

import java.util.Arrays;

public class DESTest_NIST8003APadding {
    public static void main(String[] args) {
        byte[] input = {'a', 'b', 'c', 'd', 'e', 'f'};
        byte[] key = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        byte[] output = {
                (byte) 0x25, (byte) 0xac, (byte) 0x8f, (byte) 0xc5,
                (byte) 0xc4, (byte) 0x2f, (byte) 0x89, (byte) 0x5d
        };

        // add padding
        byte[] padded_input = PaddingUtils.add_nist_8003a_padding(input, DESConst.DES_BLOCK_SIZE);

        // encrypt and decrypt
        byte[] encrypted_message = DESUtils.des_operate(padded_input, key, OperationType.ENCRYPT);
        byte[] decrypted_message = DESUtils.des_operate(encrypted_message, key, OperationType.DECRYPT);

        // remove padding
        byte[] pad_removed_bytes = PaddingUtils.remove_nist_8003a_padding(decrypted_message);

        // print result
        System.out.println(Arrays.equals(output, encrypted_message));
        System.out.println(Arrays.equals(input, pad_removed_bytes));
    }
}
