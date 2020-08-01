package lsieun.crypto.hash.updateable;

import lsieun.utils.ByteDashboard;

import java.util.Arrays;

public class Digest {
    public static void update_digest(DigestCtx context, byte[] input) {
        context.input_len += input.length;

        ByteDashboard bd = new ByteDashboard(input);

        while (bd.hasNext()) {
            byte b = bd.next();
            context.input_block[context.block_len] = b;
            context.block_len += 1;

            if (context.block_len == HashConst.DIGEST_BLOCK_SIZE) {
                context.block_algorithm.block_operate(context.input_block, context.hash);
                Arrays.fill(context.input_block, (byte) 0);
                context.block_len = 0;
            }
        }
    }

    /**
     * Process whatever’s left over in the context buffer, append
     * the length in bits, and update the hash one last time.
     */
    public static byte[] finalize_digest(DigestCtx context) {
        int block_len = context.block_len;
        byte[] input_block = Arrays.copyOf(context.input_block, context.input_block.length);
        int[] hash = Arrays.copyOf(context.hash, context.hash.length);

        if (block_len >= 56) {
            input_block[block_len] = (byte) 0x80;
            context.block_algorithm.block_operate(input_block, hash);

            Arrays.fill(input_block, (byte) 0);
            context.finalize_algorithm.block_finalize(input_block, context.input_len * 8);
            context.block_algorithm.block_operate(input_block, hash);
        } else {
            input_block[block_len] = (byte) 0x80;
            context.finalize_algorithm.block_finalize(input_block, context.input_len * 8);
            context.block_algorithm.block_operate(input_block, hash);
        }

        return context.encode_algorithm.encode(hash);
    }

    public static byte[] hmac(byte[] key_bytes, byte[] input, HashContextFunction context_algorithm) {
        int block_size = 64;
        byte[] standard_key_bytes = new byte[block_size];

        int key_length = key_bytes.length;

        if (key_length > block_size) {
            DigestCtx ctx = context_algorithm.get();
            update_digest(ctx, key_bytes);
            byte[] key_hash_bytes = finalize_digest(ctx);
            System.arraycopy(key_hash_bytes, 0, standard_key_bytes, 0, key_hash_bytes.length);
        }
        else if (key_length < block_size) {
            System.arraycopy(key_bytes, 0, standard_key_bytes, 0, key_length);
        }
        else {
            System.arraycopy(key_bytes, 0, standard_key_bytes, 0, block_size);
        }

        byte[] inner_key_pad = new byte[block_size];
        Arrays.fill(inner_key_pad, (byte) 0x36);
        xor(inner_key_pad, standard_key_bytes, block_size);

        DigestCtx ctx1 = context_algorithm.get();
        update_digest(ctx1, inner_key_pad);
        update_digest(ctx1, input);
        byte[] digest_bytes1 = finalize_digest(ctx1);

        byte[] outer_key_pad = new byte[block_size];
        Arrays.fill(outer_key_pad, (byte) 0x5c);
        xor(outer_key_pad, standard_key_bytes, block_size);

        DigestCtx ctx2 = context_algorithm.get();
        update_digest(ctx2, outer_key_pad);
        update_digest(ctx2, digest_bytes1);
        byte[] digest_bytes2 = finalize_digest(ctx2);
        return digest_bytes2;
    }

    public static void xor(byte[] dest_bytes, byte[] src_bytes, int len) {
        for (int i=0;i<len;i++) {
            dest_bytes[i] = (byte)((dest_bytes[i] & 0xFF) ^ (src_bytes[i] & 0xFF));
        }
    }
}
