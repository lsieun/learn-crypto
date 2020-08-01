package lsieun.crypto.sym.aes;

import lsieun.crypto.sym.modes.CBCUtils;
import lsieun.crypto.sym.modes.CTRUtils;
import lsieun.utils.ByteUtils;

import java.util.ArrayList;
import java.util.List;

// TODO: 我应该依照AES官方文档给出示例自己也写一个随时查看的文档
// TODO: 我应该整理一个最终版本的加密算法，里面尽可能的利用已有的结构来提升效率，
// TODO： 同时测定不同的算法加密数据的速度，有一个最终的版本
public class AESUtils {
    public static void rot_word(byte[] word_bytes) {
        byte tmp = word_bytes[0];
        word_bytes[0] = word_bytes[1];
        word_bytes[1] = word_bytes[2];
        word_bytes[2] = word_bytes[3];
        word_bytes[3] = tmp;
    }

    public static void sub_word(byte[] word_bytes) {
        for (int i = 0; i < 4; i++) {
            word_bytes[i] = (byte) AESConst.sbox[(word_bytes[i] & 0xF0) >> 4][word_bytes[i] & 0x0F];
        }
    }

    public static List<byte[]> compute_key_schedule(byte[] key_bytes) {
        int key_length = key_bytes.length;
        int key_words = key_length >> 2;
        int rcon = 0x01;

        List<byte[]> list = new ArrayList<>();
        for (int i = 0; i < key_words; i++) {
            byte[] word_bytes = new byte[4];
            System.arraycopy(key_bytes, i * 4, word_bytes, 0, 4);
            list.add(word_bytes);
        }

        for (int i = key_words; i < 4 * (key_words + 7); i++) {
            byte[] word_bytes = new byte[4];
            System.arraycopy(list.get(i - 1), 0, word_bytes, 0, 4);
            if (i % key_words == 0) {
                rot_word(word_bytes);
                sub_word(word_bytes);
                if ((rcon & 0xFF) == 0) { // TODO: 为什么这个时候变成0x1b呢？我没有读懂
                    rcon = 0x1b;
                }

                word_bytes[0] = (byte) ((word_bytes[0] & 0xFF) ^ rcon);
                rcon <<= 1;
            } else if ((key_words > 6) && (i % key_words == 4)) {
                sub_word(word_bytes);
            }
            xor(word_bytes, list.get(i - key_words), 4);

            list.add(word_bytes);
        }
        return list;
    }

    public static void xor(byte[] target_bytes, byte[] src_bytes, int length) {
        for (int i = 0; i < length; i++) {
            target_bytes[i] = (byte) ((target_bytes[i] & 0xFF) ^ (src_bytes[i] & 0xFF));
        }
    }

    public static void add_round_key(byte[][] state, byte[][] word) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = (byte) (state[r][c] ^ word[r][c]);
            }
        }
    }

    public static void sub_bytes(byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = (byte) AESConst.sbox[(state[r][c] & 0xF0) >> 4][state[r][c] & 0x0F];
            }
        }
    }

    public static void inv_sub_bytes(byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = (byte) AESConst.inv_sbox[(state[r][c] & 0xF0) >> 4][state[r][c] & 0x0F];
            }
        }
    }

    public static void shift_rows(byte[][] state) {
        byte tmp;
        tmp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = tmp;

        tmp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = tmp;
        tmp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = tmp;

        tmp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = tmp;
    }

    public static void inv_shift_rows(byte[][] state) {
        byte tmp = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = state[1][3];
        state[1][3] = tmp;

        tmp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = tmp;
        tmp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = tmp;

        tmp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = tmp;
    }

    public static byte xtime(byte x) {
        return (byte) (((x & 0xFF) << 1) ^ (((x & 0x80) != 0) ? 0x1b : 0x00));
    }

    public static byte dot(byte x, byte y) {
        int product = 0;

        for (byte mask = 0x01; mask != 0; mask <<= 1) {
            if ((y & mask) != 0) {
                product ^= (x & 0xFF);
            }
            x = xtime(x);
        }

        return (byte) product;
    }

    public static void mix_columns(byte[][] s) {
        int[] t = new int[4];
        for (int c = 0; c < 4; c++) {
            t[0] = dot((byte) 2, s[0][c]) ^ dot((byte) 3, s[1][c]) ^ s[2][c] ^ s[3][c];
            t[1] = s[0][c] ^ dot((byte) 2, s[1][c]) ^ dot((byte) 3, s[2][c]) ^ s[3][c];
            t[2] = s[0][c] ^ s[1][c] ^ dot((byte) 2, s[2][c]) ^ dot((byte) 3, s[3][c]);
            t[3] = dot((byte) 3, s[0][c]) ^ s[1][c] ^ s[2][c] ^ dot((byte) 2, s[3][c]);

            s[0][c] = (byte) t[0];
            s[1][c] = (byte) t[1];
            s[2][c] = (byte) t[2];
            s[3][c] = (byte) t[3];
        }
    }

    public static void inv_mix_columns(byte[][] s) {
        int[] t = new int[4];
        for (int c = 0; c < 4; c++) {
            t[0] = dot((byte) 0x0e, s[0][c]) ^ dot((byte) 0x0b, s[1][c]) ^
                    dot((byte) 0x0d, s[2][c]) ^ dot((byte) 0x09, s[3][c]);
            t[1] = dot((byte) 0x09, s[0][c]) ^ dot((byte) 0x0e, s[1][c]) ^
                    dot((byte) 0x0b, s[2][c]) ^ dot((byte) 0x0d, s[3][c]);
            t[2] = dot((byte) 0x0d, s[0][c]) ^ dot((byte) 0x09, s[1][c]) ^
                    dot((byte) 0x0e, s[2][c]) ^ dot((byte) 0x0b, s[3][c]);
            t[3] = dot((byte) 0x0b, s[0][c]) ^ dot((byte) 0x0d, s[1][c]) ^
                    dot((byte) 0x09, s[2][c]) ^ dot((byte) 0x0e, s[3][c]);
            s[0][c] = (byte) t[0];
            s[1][c] = (byte) t[1];
            s[2][c] = (byte) t[2];
            s[3][c] = (byte) t[3];
        }
    }

    public static void fill_word_bytes(List<byte[]> list, int i, byte[][] word_bytes) {
        for (int c = 0; c < 4; c++) {
            byte[] bytes = list.get(i + c);
            for (int r = 0; r < 4; r++) {
                word_bytes[r][c] = bytes[r];
            }
        }
    }

    public static void from_block_to_state(byte[] input_block, byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = input_block[r + (4 * c)];
            }
        }
    }

    public static void from_state_to_block(byte[] output_block, byte[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                output_block[r + (4 * c)] = state[r][c];
            }
        }
    }

    public static byte[] aes_block_encrypt(byte[] input_block, byte[] key_bytes) {
        int key_size = key_bytes.length;
        byte[][] state = new byte[4][4];
        from_block_to_state(input_block, state);


        // rounds = key size in 4-byte words + 6
        int nr = (key_size >> 2) + 6;

        List<byte[]> key_list_bytes = compute_key_schedule(key_bytes);
        byte[][] word_bytes = new byte[4][4];
        fill_word_bytes(key_list_bytes, 0, word_bytes);

        add_round_key(state, word_bytes);

        for (int round = 0; round < nr; round++) {
            sub_bytes(state);

            shift_rows(state);

            if (round < (nr - 1)) {
                mix_columns(state);
            }

            fill_word_bytes(key_list_bytes, (round + 1) * 4, word_bytes);

            add_round_key(state, word_bytes);
        }

        byte[] output_block = new byte[AESConst.AES_BLOCK_SIZE];
        from_state_to_block(output_block, state);
        return output_block;
    }

    public static byte[] aes_block_decrypt(byte[] input_block, byte[] key_bytes) {
        int key_size = key_bytes.length;
        byte[][] state = new byte[4][4];

        from_block_to_state(input_block, state);

        // rounds = key size in 4-byte words + 6
        int nr = (key_size >> 2) + 6;

        List<byte[]> key_list_bytes = compute_key_schedule(key_bytes);

        byte[][] word_bytes = new byte[4][4];
        fill_word_bytes(key_list_bytes, nr * 4, word_bytes);

        add_round_key(state, word_bytes);

        for (int round = nr; round > 0; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            fill_word_bytes(key_list_bytes, (round - 1) * 4, word_bytes);
            add_round_key(state, word_bytes);
            if (round > 1) {
                inv_mix_columns(state);
            }
        }

        byte[] output_block = new byte[AESConst.AES_BLOCK_SIZE];
        from_state_to_block(output_block, state);
        return output_block;
    }

    // TODO: key生成key schedule之后，应该进行缓存，因为它可以进行复用
    public static void aes_encrypt(byte[] input, int input_len, byte[] output, byte[] iv_128_bit_bytes, byte[] key, int key_length) {
        int count = input_len / AESConst.AES_BLOCK_SIZE;

        byte[] input_block = new byte[AESConst.AES_BLOCK_SIZE];
        byte[] iv_block = new byte[AESConst.AES_BLOCK_SIZE];

        System.arraycopy(iv_128_bit_bytes, 0, iv_block, 0, AESConst.AES_BLOCK_SIZE);

        for (int i = 0; i < count; i++) {
            System.arraycopy(input, i * AESConst.AES_BLOCK_SIZE, input_block, 0, AESConst.AES_BLOCK_SIZE);
            xor(input_block, iv_block, AESConst.AES_BLOCK_SIZE);
            byte[] output_block = aes_block_encrypt(input_block, key);
            System.arraycopy(output_block, 0, iv_block, 0, AESConst.AES_BLOCK_SIZE);
            System.arraycopy(output_block, 0, output, i * AESConst.AES_BLOCK_SIZE, AESConst.AES_BLOCK_SIZE);
        }
    }

    public static void aes_decrypt(byte[] input, int input_len, byte[] output, byte[] iv_128_bit_bytes, byte[] key_bytes, int key_length) {
        int count = input_len / AESConst.AES_BLOCK_SIZE;

        byte[] input_block = new byte[AESConst.AES_BLOCK_SIZE];
        byte[] iv_block = new byte[AESConst.AES_BLOCK_SIZE];

        System.arraycopy(iv_128_bit_bytes, 0, iv_block, 0, AESConst.AES_BLOCK_SIZE);

        for (int i = 0; i < count; i++) {
            System.arraycopy(input, i * AESConst.AES_BLOCK_SIZE, input_block, 0, AESConst.AES_BLOCK_SIZE);
            byte[] output_block = aes_block_decrypt(input_block, key_bytes);
            xor(output_block, iv_block, AESConst.AES_BLOCK_SIZE);
            System.arraycopy(input_block, 0, iv_block, 0, AESConst.AES_BLOCK_SIZE);
            System.arraycopy(output_block, 0, output, i * AESConst.AES_BLOCK_SIZE, AESConst.AES_BLOCK_SIZE);
        }

    }

    public static void aes_128_encrypt(byte[] plain_text_bytes, int plain_text_len, byte[] cipher_text_bytes, byte[] iv_128_bit_bytes, byte[] key_bytes) {
        aes_encrypt(plain_text_bytes, plain_text_len, cipher_text_bytes, iv_128_bit_bytes, key_bytes, 16);
    }

    public static void aes_128_decrypt(byte[] cipher_text_bytes, int cipher_text_len, byte[] plain_text_bytes, byte[] iv_128_bit_bytes, byte[] key_bytes) {
        aes_decrypt(cipher_text_bytes, cipher_text_len, plain_text_bytes, iv_128_bit_bytes, key_bytes, 16);
    }

    public static void aes_256_encrypt(byte[] plain_text_bytes, int plain_text_len, byte[] cipher_text_bytes, byte[] iv_128_bit_bytes, byte[] key_bytes) {
        aes_encrypt(plain_text_bytes, plain_text_len, cipher_text_bytes, iv_128_bit_bytes, key_bytes, 32);
    }

    public static void aes_256_decrypt(byte[] cipher_text_bytes, int cipher_text_len, byte[] plain_text_bytes, byte[] iv_128_bit_bytes, byte[] key_bytes) {
        aes_decrypt(cipher_text_bytes, cipher_text_len, plain_text_bytes, iv_128_bit_bytes, key_bytes, 32);
    }

    public static byte[] aes_cbc_encrypt(byte[] input, byte[] key, byte[] iv) {
        return CBCUtils.cbc_encrypt(input, key, iv, AESConst.AES_BLOCK_SIZE, AESUtils::aes_block_encrypt);
    }

    public static byte[] aes_cbc_decrypt(byte[] input, byte[] key, byte[] iv) {
        return CBCUtils.cbc_encrypt(input, key, iv, AESConst.AES_BLOCK_SIZE, AESUtils::aes_block_decrypt);
    }

    public static byte[] aes_ctr_encrypt(byte[] input, byte[] key, byte[] iv) {
        return CTRUtils.operate(input, key, iv, AESConst.AES_BLOCK_SIZE, AESUtils::aes_block_encrypt);
    }

    public static byte[] aes_ctr_decrypt(byte[] input, byte[] key, byte[] iv) {
        return CTRUtils.operate(input, key, iv, AESConst.AES_BLOCK_SIZE, AESUtils::aes_block_encrypt);
    }

    public static byte[] aes_cbc_mac(byte[] input, byte[] key, int mac_length) {
        return CBCUtils.cbc_mac(input, key, AESConst.AES_BLOCK_SIZE, mac_length, AESUtils::aes_block_encrypt);
    }

    public static byte[] aes_ccm_encrypt(byte[] input, byte[] key, byte[] iv, int mac_length) {
        int input_length = input.length;
        byte[] output = new byte[input_length + mac_length];

        int block_size = AESConst.AES_BLOCK_SIZE;

        // The first input block is a (complicated) standardized header
        // This is just for the MAC; not output
        byte[] input_block = new byte[block_size];
        input_block[0] = 0x1F; // t = mac_length = 8 bytes, q = 8 bytes (so n = 7)
        System.arraycopy(iv, 0, input_block, 1, 8);
        byte[] header_length_bytes = ByteUtils.toBytes(input_length);
        System.arraycopy(header_length_bytes, 0, input_block, block_size - header_length_bytes.length, header_length_bytes.length);

        // update the CBC-MAC
        byte[] mac_block = new byte[block_size];
        input_block = ByteUtils.xor(input_block, mac_block, block_size);
        byte[] output_block = aes_block_encrypt(input_block, key);
        System.arraycopy(output_block, 0, mac_block, 0, block_size);

        // Prepare the first nonce
        byte[] nonce = new byte[block_size];
        nonce[0] = 0x07; // q hardcode to 8 bytes, so n = 7
        System.arraycopy(iv, 0, nonce, 1, 8);

        int times = input_length / block_size;
        int remaining = input_length % block_size;
        for (int i = 0; i < times; i++) {
            System.arraycopy(input, i * block_size, input_block, 0, block_size);

            // Increment counter
            ByteUtils.add_one(nonce, 4);

            // encrypt the nonce
            byte[] encrypted_bytes = aes_block_encrypt(nonce, key);
            byte[] xor_bytes = ByteUtils.xor(encrypted_bytes, input_block, block_size); // implement CTR
            System.arraycopy(xor_bytes, 0, output, i * block_size, block_size);

            // update the CBC-MAC
            byte[] xor_bytes2 = ByteUtils.xor(input_block, mac_block, block_size);
            byte[] encrypted_bytes2 = aes_block_encrypt(xor_bytes, key);
            System.arraycopy(encrypted_bytes2, 0, mac_block, 0, block_size);
        }

        if (remaining > 0) {
            ByteUtils.setAll(input_block, 0);
            System.arraycopy(input, times * block_size, input_block, 0, remaining);
            // Increment counter
            ByteUtils.add_one(nonce, 4);

            // encrypt the nonce
            byte[] encrypted_bytes = aes_block_encrypt(nonce, key);
            byte[] xor_bytes = ByteUtils.xor(encrypted_bytes, input_block, remaining); // implement CTR
            System.arraycopy(xor_bytes, 0, output, times * block_size, remaining);

            // update the CBC-MAC
            ByteUtils.setAll(input_block, 0);
            System.arraycopy(input, times * block_size, input_block, 0, remaining);
            byte[] xor_bytes2 = ByteUtils.xor(input_block, mac_block, block_size);
            byte[] encrypted_bytes2 = aes_block_encrypt(xor_bytes, key);
            System.arraycopy(encrypted_bytes2, 0, mac_block, 0, block_size);
        }

        // Regenerate the first nonce
        ByteUtils.setAll(nonce, 0);
        nonce[0] = 0x07; // q hardcode to 8 bytes
        System.arraycopy(iv, 0, nonce, 1, 8);

        // encrypt the header and output it
        byte[] encrypted_bytes3 = aes_block_encrypt(nonce, key);

        // MAC is the CBC-mac XOR’ed with S0
        byte[] mac_bytes = ByteUtils.xor(encrypted_bytes3, mac_block, mac_length);
        System.arraycopy(mac_bytes, 0, output, input_length, mac_length);

        return output;
    }
}
