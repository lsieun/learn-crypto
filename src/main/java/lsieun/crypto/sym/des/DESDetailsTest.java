package lsieun.crypto.sym.des;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.HexUtils;

public class DESDetailsTest {
    public static void main(String[] args) {
        byte[] input_bytes = DESSample.input;
        byte[] key_bytes = DESSample.key;

        byte[] encrypted_bytes = DESDetails.des_block_operate(input_bytes, key_bytes, OperationType.ENCRYPT);
        byte[] decrypted_bytes = DESDetails.des_block_operate(encrypted_bytes, key_bytes, OperationType.DECRYPT);

        System.out.println(HexUtils.toHex(encrypted_bytes));
        System.out.println(HexUtils.toHex(decrypted_bytes));
    }
}
