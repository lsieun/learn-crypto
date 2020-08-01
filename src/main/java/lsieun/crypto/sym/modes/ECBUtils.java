package lsieun.crypto.sym.modes;

import lsieun.crypto.sym.BlockOperation;

public class ECBUtils {
    public static byte[] ecb_encrypt(byte[] input, byte[] key, int block_size, BlockOperation block_encrypt_algorithm) {
        return ecb_operate(input, key, block_size, block_encrypt_algorithm);
    }

    public static byte[] ecb_decrypt(byte[] input, byte[] key, int block_size, BlockOperation block_decrypt_algorithm) {
        return ecb_operate(input, key, block_size, block_decrypt_algorithm);
    }

    public static byte[] ecb_operate(byte[] input, byte[] key, int block_size, BlockOperation block_algorithm) {
        int input_length = input.length;
        if (input_length % block_size != 0) {
            throw new IllegalArgumentException("input's length is not valid");
        }

        byte[] output = new byte[input_length];
        byte[] input_block = new byte[block_size];
        int times = input_length / block_size;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);
            byte[] encrypted_bytes = block_algorithm.block_operate(input_block, key);
            System.arraycopy(encrypted_bytes, 0, output, i * block_size, block_size);
        }
        return output;
    }
}
