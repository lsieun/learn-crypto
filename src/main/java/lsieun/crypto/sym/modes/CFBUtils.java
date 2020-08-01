package lsieun.crypto.sym.modes;

import lsieun.crypto.sym.BlockOperation;
import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

public class CFBUtils {
    public static byte[] encrypt(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm) {
        return operate(input, key, iv, block_size, block_algorithm, OperationType.ENCRYPT);
    }

    public static byte[] decrypt(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm) {
        return operate(input, key, iv, block_size, block_algorithm, OperationType.DECRYPT);
    }

    public static byte[] operate(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm, OperationType operation) {
        int input_length = input.length;
        if (input_length % block_size != 0) {
            throw new IllegalArgumentException("input's length is not valid");
        }

        int iv_length = iv.length;
        if (iv_length != block_size) {
            throw new IllegalArgumentException("iv's length is not valid");
        }

        byte[] output = new byte[input_length];
        byte[] input_block = new byte[block_size];

        int times = input_length / block_size;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);
            if (operation == OperationType.ENCRYPT) {
                byte[] encrypted_bytes = block_algorithm.block_operate(iv, key);
                byte[] xor_bytes = ByteUtils.xor(input_block, encrypted_bytes, block_size);

                System.arraycopy(xor_bytes, 0, output, i * block_size, block_size);
                System.arraycopy(xor_bytes, 0, iv, 0, block_size);
            }
            if (operation == OperationType.DECRYPT) {
                byte[] encrypted_bytes = block_algorithm.block_operate(iv, key);
                byte[] xor_bytes = ByteUtils.xor(input_block, encrypted_bytes, block_size);
                System.arraycopy(xor_bytes, 0, output, i * block_size, block_size);
                System.arraycopy(input_block, 0, iv, 0, block_size);
            }

        }
        return output;
    }
}
