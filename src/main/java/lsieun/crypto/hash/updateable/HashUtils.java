package lsieun.crypto.hash.updateable;

import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.crypto.hash.sha256.SHA256Const;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HashUtils {
    public static byte[] md5(byte[] input) {
        int[] hash = Arrays.copyOf(HashConst.INITIAL_HASH, 4);
        return HashUtils.digest_hash(input, hash, MD5Utils::md5_block_operate, HashUtils::md5_finalize, HashUtils::little_endian_encode);
    }

    public static byte[] sha1(byte[] input) {
        int[] hash = Arrays.copyOf(HashConst.INITIAL_HASH, 5);
        return HashUtils.digest_hash(input, hash, SHA1Utils::sha1_block_operate, HashUtils::sha_finalize, HashUtils::big_endian_encode);
    }

    public static byte[] sha256(byte[] input) {
        int[] hash = Arrays.copyOf(SHA256Const.SHA256_INITIAL_HASH, 8);
        return HashUtils.digest_hash(input, hash, SHA256Utils::sha256_block_operate, HashUtils::sha_finalize, HashUtils::big_endian_encode);
    }

    public static byte[] digest_hash(byte[] input, int[] hash,
                                     HashBlockFunction block_algorithm,
                                     HashFinalizeFunction finalize_algorithm,
                                     HashEncodeFunction encode_algorithm
    ) {
        int len = input.length;
        long length_in_bits = len * 8;

        int quotient = len / HashConst.DIGEST_BLOCK_SIZE;
        int remainder = len % HashConst.DIGEST_BLOCK_SIZE;
        byte[] input_block = new byte[HashConst.DIGEST_BLOCK_SIZE];
        for (int i = 0; i < quotient; i++) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, i * HashConst.DIGEST_BLOCK_SIZE, input_block, 0, HashConst.DIGEST_BLOCK_SIZE);
            block_algorithm.block_operate(input_block, hash);
        }

        if (remainder >= HashConst.PADDING_THRESHOLD) {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * HashConst.DIGEST_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            block_algorithm.block_operate(input_block, hash);

            Arrays.fill(input_block, (byte) 0);
            finalize_algorithm.block_finalize(input_block, length_in_bits);
            block_algorithm.block_operate(input_block, hash);
        } else {
            Arrays.fill(input_block, (byte) 0);
            System.arraycopy(input, quotient * HashConst.DIGEST_BLOCK_SIZE, input_block, 0, remainder);
            input_block[remainder] = (byte) 0x80;
            finalize_algorithm.block_finalize(input_block, length_in_bits);
            block_algorithm.block_operate(input_block, hash);
        }

        return encode_algorithm.encode(hash);
    }

    public static void md5_finalize(byte[] padded_block, long length_in_bits) {
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 1] = (byte) ((length_in_bits >>> 56) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 2] = (byte) ((length_in_bits >>> 48) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 3] = (byte) ((length_in_bits >>> 40) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 4] = (byte) ((length_in_bits >>> 32) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 5] = (byte) ((length_in_bits >>> 24) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 6] = (byte) ((length_in_bits >>> 16) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 7] = (byte) ((length_in_bits >>> 8) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 8] = (byte) (length_in_bits & 0xFF);
    }

    public static void sha_finalize(byte[] padded_block, long length_in_bits) {
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 8] = (byte) ((length_in_bits >>> 56) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 7] = (byte) ((length_in_bits >>> 48) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 6] = (byte) ((length_in_bits >>> 40) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 5] = (byte) ((length_in_bits >>> 32) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 4] = (byte) ((length_in_bits >>> 24) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 3] = (byte) ((length_in_bits >>> 16) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 2] = (byte) ((length_in_bits >>> 8) & 0xFF);
        padded_block[HashConst.DIGEST_BLOCK_SIZE - 1] = (byte) (length_in_bits & 0xFF);

    }

    public static byte[] little_endian_encode(int[] hash) {
        int len = hash.length;
        byte[] bytes = new byte[len * 4];

        for (int i = 0; i < len; i++) {
            bytes[i * 4 + 0] = (byte) ((hash[i] >>> 0) & 0xFF);
            bytes[i * 4 + 1] = (byte) ((hash[i] >>> 8) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((hash[i] >>> 16) & 0xFF);
            bytes[i * 4 + 3] = (byte) ((hash[i] >>> 24) & 0xFF);
        }

        return bytes;
    }

    public static byte[] big_endian_encode(int[] hash) {
        int len = hash.length;
        byte[] bytes = new byte[len * 4];

        for (int i = 0; i < len; i++) {
            bytes[i * 4 + 0] = (byte) ((hash[i] >>> 24) & 0xFF);
            bytes[i * 4 + 1] = (byte) ((hash[i] >>> 16) & 0xFF);
            bytes[i * 4 + 2] = (byte) ((hash[i] >>> 8) & 0xFF);
            bytes[i * 4 + 3] = (byte) ((hash[i] >>> 0) & 0xFF);
        }

        return bytes;
    }


    public static void main(String[] args) {
        byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        byte[] bytes = HashUtils.sha256(input);

        String hex_str = HexUtils.format(bytes, HexFormat.FORMAT_FF_SPACE_FF);
        System.out.println(hex_str);
    }

}
