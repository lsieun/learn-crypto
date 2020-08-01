package lsieun.crypto.hash.updateable;

@FunctionalInterface
public interface HashBlockFunction {
    void block_operate(byte[] input, int[] hash);
}
