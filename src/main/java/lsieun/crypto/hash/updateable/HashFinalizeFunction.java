package lsieun.crypto.hash.updateable;

@FunctionalInterface
public interface HashFinalizeFunction {
    void block_finalize(byte[] padded_block, long length_in_bits);
}
