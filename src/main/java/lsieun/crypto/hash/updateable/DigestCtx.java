package lsieun.crypto.hash.updateable;

import lsieun.crypto.hash.md5.MD5Const;
import lsieun.crypto.hash.md5.MD5Utils;
import lsieun.crypto.hash.sha1.SHA1Const;
import lsieun.crypto.hash.sha1.SHA1Utils;
import lsieun.crypto.hash.sha256.SHA256Const;
import lsieun.crypto.hash.sha256.SHA256Utils;
import lsieun.utils.HexUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DigestCtx {
    public final int[] hash;
    public long input_len;

    public final HashBlockFunction block_algorithm;
    public final HashFinalizeFunction finalize_algorithm;
    public final HashEncodeFunction encode_algorithm;

    // Temporary storage
    public final byte[] input_block = new byte[HashConst.DIGEST_BLOCK_SIZE];
    public int block_len;

    public DigestCtx(int[] hash, HashBlockFunction block_algorithm, HashFinalizeFunction finalize_algorithm, HashEncodeFunction encode_algorithm) {
        this.hash = hash;
        this.block_algorithm = block_algorithm;
        this.finalize_algorithm = finalize_algorithm;
        this.encode_algorithm = encode_algorithm;

        this.input_len = 0;
        this.block_len = 0;
    }

    public static DigestCtx new_md5_digest() {
        int[] hash = Arrays.copyOf(MD5Const.MD5_INITIAL_HASH, 4);
        return new DigestCtx(hash, MD5Utils::md5_block_operate, HashUtils::md5_finalize, HashUtils::little_endian_encode);
    }

    public static DigestCtx new_sha1_digest() {
        int[] hash = Arrays.copyOf(SHA1Const.SHA1_INITIAL_HASH, 5);
        return new DigestCtx(hash, SHA1Utils::sha1_block_operate, HashUtils::sha_finalize, HashUtils::big_endian_encode);
    }

    public static DigestCtx new_sha256_digest() {
        int[] hash = Arrays.copyOf(SHA256Const.SHA256_INITIAL_HASH, 8);
        return new DigestCtx(hash, SHA256Utils::sha256_block_operate, HashUtils::sha_finalize, HashUtils::big_endian_encode);
    }

    public static void main(String[] args) {
        byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
        DigestCtx ctx = DigestCtx.new_md5_digest();
        Digest.update_digest(ctx, input);
        byte[] digest = Digest.finalize_digest(ctx);
        System.out.println(HexUtils.toHex(digest));
    }
}
