package lsieun.crypto.sym.modes;

import lsieun.crypto.sym.BlockOperation;
import lsieun.crypto.sym.OperationType;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

public class CBCUtils {

    public static byte[] cbc_encrypt(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm) {
        return cbc_operate(input, key, iv, block_size, block_algorithm, OperationType.ENCRYPT);
    }

    public static byte[] cbc_decrypt(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm) {
        return cbc_operate(input, key, iv, block_size, block_algorithm, OperationType.DECRYPT);
    }

    public static byte[] cbc_operate(byte[] input, byte[] key, byte[] iv, int block_size, BlockOperation block_algorithm, OperationType operation) {
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
                byte[] xor_bytes = ByteUtils.xor(input_block, iv, block_size);
                byte[] encrypted_bytes = block_algorithm.block_operate(xor_bytes, key);
                System.arraycopy(encrypted_bytes, 0, output, i * block_size, block_size);
                System.arraycopy(encrypted_bytes, 0, iv, 0, block_size);
            }
            if (operation == OperationType.DECRYPT) {
                byte[] decrypted_bytes = block_algorithm.block_operate(input_block, key);
                byte[] xor_bytes = ByteUtils.xor(decrypted_bytes, iv, block_size);
                System.arraycopy(xor_bytes, 0, output, i * block_size, block_size);
                System.arraycopy(input_block, 0, iv, 0, block_size);
            }

        }
        return output;
    }

    public static byte[] cbc_mac(byte[] input, byte[] key, int block_size, int mac_length, BlockOperation block_algorithm) {
        if (mac_length < 1 || mac_length > block_size) {
            throw new IllegalArgumentException("mac_length is not legal: " + mac_length);
        }

        byte[] input_block = new byte[block_size];
        byte[] mac_block = new byte[block_size];

        int input_length = input.length;
        int times = input_length / block_size;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);
            byte[] xor_bytes = ByteUtils.xor(input_block, mac_block, block_size);
            byte[] output_block = block_algorithm.block_operate(xor_bytes, key);
            System.arraycopy(output_block, 0, mac_block, 0, block_size);
        }
        return Arrays.copyOf(mac_block, mac_length);
    }
}
