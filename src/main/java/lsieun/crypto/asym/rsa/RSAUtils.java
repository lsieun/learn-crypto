package lsieun.crypto.asym.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RSAUtils {
    public static byte[] rsa_encrypt(byte[] input, RSAKey rsaKey) {
        int bit_length = rsaKey.modulus.bitLength();
        int quotient = bit_length / 8;
        int remainder = bit_length % 8;
        int modulus_length = quotient;
        if (remainder != 0) {
            modulus_length += 1;
        }

        byte[] padded_block = new byte[modulus_length];
        int length = input.length;
        int index = 0;

        List<Byte> list = new ArrayList<>();
        while (length > 0) {
            int block_size = Math.min(length, modulus_length - 11);
            Arrays.fill(padded_block, (byte) 0);
            System.arraycopy(input, index, padded_block, modulus_length - block_size, block_size);
            // set block type
            padded_block[1] = 0x02;

            for (int i = 2; i < (modulus_length - block_size - 1); i++) {
                // TODO make these random
                padded_block[i] = (byte) i;
            }

            BigInteger m = new BigInteger(1, padded_block);
            BigInteger c = m.modPow(rsaKey.exponent, rsaKey.modulus);
            byte[] bytes = c.toByteArray();

            Arrays.fill(padded_block, (byte) 0);
            for (int i = modulus_length - 1, j = bytes.length - 1; i >= 0 && j >= 0; i--, j--) {
                padded_block[i] = bytes[j];
            }
            for (byte b : padded_block) {
                list.add(b);
            }

            index += block_size;
            length -= block_size;
        }

        int size = list.size();
        byte[] result_bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            result_bytes[i] = list.get(i);
        }
        return result_bytes;
    }

    public static byte[] rsa_decrypt(byte[] input, RSAKey rsaKey) {
        int bit_length = rsaKey.modulus.bitLength();
        int quotient = bit_length / 8;
        int remainder = bit_length % 8;
        int modulus_length = quotient;
        if (remainder != 0) {
            modulus_length += 1;
        }

        byte[] padded_block = new byte[modulus_length];
        int length = input.length;
        int index = 0;

        List<Byte> list = new ArrayList<>();
        while (length > 0) {
            if (length < modulus_length) {
                throw new RuntimeException("Error - input must be an even multiple of key modulus");
            }

            System.arraycopy(input, index, padded_block, 0, modulus_length);
            BigInteger c = new BigInteger(1, padded_block);
            BigInteger m = c.modPow(rsaKey.exponent, rsaKey.modulus);
            byte[] bytes = m.toByteArray();

            Arrays.fill(padded_block, (byte) 0);
            for (int i = modulus_length - 1, j = bytes.length - 1; i >= 0 && j >= 0; i--, j--) {
                padded_block[i] = bytes[j];
            }

            if (padded_block[1] > 0x02) {
                throw new RuntimeException("Decryption error or unrecognized block type: " + padded_block[1]);
            }
            int i = 2;
            while (padded_block[i] != 0) {
                i++;
            }
            i++;
            while (i < modulus_length) {
                list.add(padded_block[i]);
                i++;
            }

            index += modulus_length;
            length -= modulus_length;
        }

        int size = list.size();
        byte[] result_bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            result_bytes[i] = list.get(i);
        }
        return result_bytes;
    }
}
