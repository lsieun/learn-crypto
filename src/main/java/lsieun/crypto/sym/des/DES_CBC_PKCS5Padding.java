package lsieun.crypto.sym.des;

import lsieun.crypto.sym.OperationType;
import lsieun.utils.PaddingUtils;

public class DES_CBC_PKCS5Padding {

    public static byte[] des_cbc_encrypt(byte[] input, byte[] key_64_bit_bytes, byte[] iv_64_bit_bytes) {
        byte[] padded_input = PaddingUtils.add_pkcs5_padding(input, DESConst.DES_BLOCK_SIZE);
        return des_cbc_operate(padded_input, key_64_bit_bytes, iv_64_bit_bytes, OperationType.ENCRYPT);
    }

    public static byte[] des_cbc_decrypt(byte[] input, byte[] key_64_bit_bytes, byte[] iv_64_bit_bytes) {
        byte[] decrypted_bytes = des_cbc_operate(input, key_64_bit_bytes, iv_64_bit_bytes, OperationType.DECRYPT);
        return PaddingUtils.remove_pkcs5_padding(decrypted_bytes);
    }

    @SuppressWarnings("Duplicates")
    public static byte[] des_cbc_operate(byte[] input, byte[] key_64_bit_bytes, byte[] iv_64_bit_bytes, OperationType operation) {
        int input_length = input.length;
        if (input_length % DESConst.DES_BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("input's length is not valid");
        }

        byte[] output = new byte[input_length];
        byte[] input_block = new byte[DESConst.DES_BLOCK_SIZE];

        byte[] iv = new byte[DESConst.DES_BLOCK_SIZE];
        System.arraycopy(iv_64_bit_bytes, 0, iv, 0, DESConst.DES_BLOCK_SIZE);

        int times = input_length / DESConst.DES_BLOCK_SIZE;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * DESConst.DES_BLOCK_SIZE, input_block, 0, DESConst.DES_BLOCK_SIZE);
            if (operation == OperationType.ENCRYPT) {
                byte[] xor_64_bit_bytes = DESUtils.xor(input_block, iv, DESConst.DES_BLOCK_SIZE);
                byte[] encrypted_bytes = DESUtils.des_block_operate(xor_64_bit_bytes, key_64_bit_bytes, operation);
                System.arraycopy(encrypted_bytes, 0, output, i * DESConst.DES_BLOCK_SIZE, DESConst.DES_BLOCK_SIZE);
                System.arraycopy(encrypted_bytes, 0, iv, 0, DESConst.DES_BLOCK_SIZE);
            }
            if (operation == OperationType.DECRYPT) {
                byte[] decrypted_bytes = DESUtils.des_block_operate(input_block, key_64_bit_bytes, operation);
                byte[] xor_64_bit_bytes = DESUtils.xor(decrypted_bytes, iv, DESConst.DES_BLOCK_SIZE);
                System.arraycopy(xor_64_bit_bytes, 0, output, i * DESConst.DES_BLOCK_SIZE, DESConst.DES_BLOCK_SIZE);
                System.arraycopy(input_block, 0, iv, 0, DESConst.DES_BLOCK_SIZE);
            }

        }
        return output;
    }
}
